/*
 * Arm PrimeCell NXP_UART UART
 *
 * Copyright (c) 2006 CodeSourcery.
 * Written by Paul Brook
 *
 * This code is licensed under the GPL.
 */

/*
 * QEMU interface:
 *  + sysbus MMIO region 0: device registers
 *  + sysbus IRQ 0: UARTINTR (combined interrupt line)
 *  + sysbus IRQ 1: UARTRXINTR (receive FIFO interrupt line)
 *  + sysbus IRQ 2: UARTTXINTR (transmit FIFO interrupt line)
 *  + sysbus IRQ 3: UARTRTINTR (receive timeout interrupt line)
 *  + sysbus IRQ 4: UARTMSINTR (momem status interrupt line)
 *  + sysbus IRQ 5: UARTEINTR (error interrupt line)
 */

 #include "qemu/osdep.h"
 #include "qapi/error.h"
 #include "hw/char/nxps32k3x8evb_uart.h"
 #include "hw/irq.h"
 #include "hw/sysbus.h"
 #include "hw/qdev-clock.h"
 #include "hw/qdev-properties.h"
 #include "hw/qdev-properties-system.h"
 #include "migration/vmstate.h"
 #include "chardev/char-fe.h"
 #include "chardev/char-serial.h"
 #include "qemu/log.h"
 #include "qemu/module.h"
 #include "trace.h"
 
 DeviceState *nxp_uart_create(hwaddr addr, qemu_irq irq, Chardev *chr)
 {
     DeviceState *dev;
     SysBusDevice *s;
 
     dev = qdev_new("nxp_uart");
     s = SYS_BUS_DEVICE(dev);
     qdev_prop_set_chr(dev, "chardev", chr);
     sysbus_realize_and_unref(s, &error_fatal);
     sysbus_mmio_map(s, 0, addr);
     sysbus_connect_irq(s, 0, irq);
 
     return dev;
 }
 
 /* Flag Register, UARTFR */
 #define NXP_UART_FLAG_RI   0x100
 #define NXP_UART_FLAG_TXFE 0x80
 #define NXP_UART_FLAG_RXFF 0x40
 #define NXP_UART_FLAG_TXFF 0x20
 #define NXP_UART_FLAG_RXFE 0x10
 #define NXP_UART_FLAG_DCD  0x04
 #define NXP_UART_FLAG_DSR  0x02
 #define NXP_UART_FLAG_CTS  0x01
 
 /* Data Register, UARTDR */
 #define DR_BE   (1 << 10)
 
 /* Interrupt status bits in UARTRIS, UARTMIS, UARTIMSC */
 #define INT_OE (1 << 10)
 #define INT_BE (1 << 9)
 #define INT_PE (1 << 8)
 #define INT_FE (1 << 7)
 #define INT_RT (1 << 6)
 #define INT_TX (1 << 5)
 #define INT_RX (1 << 4)
 #define INT_DSR (1 << 3)
 #define INT_DCD (1 << 2)
 #define INT_CTS (1 << 1)
 #define INT_RI (1 << 0)
 #define INT_E (INT_OE | INT_BE | INT_PE | INT_FE)
 #define INT_MS (INT_RI | INT_DSR | INT_DCD | INT_CTS)
 
 /* Line Control Register, UARTLCR_H */
 #define LCR_FEN     (1 << 4)
 #define LCR_BRK     (1 << 0)
 
 /* Control Register, UARTCR */
 #define CR_OUT2     (1 << 13)
 #define CR_OUT1     (1 << 12)
 #define CR_RTS      (1 << 11)
 #define CR_DTR      (1 << 10)
 #define CR_RXE      (1 << 9)
 #define CR_TXE      (1 << 8)
 #define CR_LBE      (1 << 7)
 #define CR_UARTEN   (1 << 0)
 
 /* Integer Baud Rate Divider, UARTIBRD */
 #define IBRD_MASK 0xffff
 
 /* Fractional Baud Rate Divider, UARTFBRD */
 #define FBRD_MASK 0x3f
 
 static const unsigned char nxp_uart_id_arm[8] =
   { 0x11, 0x10, 0x14, 0x00, 0x0d, 0xf0, 0x05, 0xb1 };
 
 static const char *nxp_uart_regname(hwaddr offset)
 {
     static const char *const rname[] = {
         [0] = "DR", [1] = "RSR", [6] = "FR", [8] = "ILPR", [9] = "IBRD",
         [10] = "FBRD", [11] = "LCRH", [12] = "CR", [13] = "IFLS", [14] = "IMSC",
         [15] = "RIS", [16] = "MIS", [17] = "ICR", [18] = "DMACR",
     };
     unsigned idx = offset >> 2;
 
     if (idx < ARRAY_SIZE(rname) && rname[idx]) {
         return rname[idx];
     }
     if (idx >= 0x3f8 && idx <= 0x400) {
         return "ID";
     }
     return "UNKN";
 }
 
 /* Which bits in the interrupt status matter for each outbound IRQ line ? */
 static const uint32_t irqmask[] = {
     INT_E | INT_MS | INT_RT | INT_TX | INT_RX, /* combined IRQ */
     INT_RX,
     INT_TX,
     INT_RT,
     INT_MS,
     INT_E,
 };
 
 static void nxp_uart_update(NXP_UART_STATE *s)
 {
     uint32_t flags;
     int i;
 
     flags = s->int_level & s->int_enabled;
     trace_nxp_uart_irq_state(flags != 0);
     for (i = 0; i < ARRAY_SIZE(s->irq); i++) {
         qemu_set_irq(s->irq[i], (flags & irqmask[i]) != 0);
     }
 }
 
 static bool nxp_uart_loopback_enabled(NXP_UART_STATE *s)
 {
     return !!(s->cr & CR_LBE);
 }
 
 static bool nxp_uart_is_fifo_enabled(NXP_UART_STATE *s)
 {
     return (s->lcr & LCR_FEN) != 0;
 }
 
 static inline unsigned nxp_uart_get_fifo_depth(NXP_UART_STATE *s)
 {
     /* Note: FIFO depth is expected to be power-of-2 */
     return nxp_uart_is_fifo_enabled(s) ? NXP_UART_FIFO_DEPTH : 1;
 }
 
 static inline void nxp_uart_reset_rx_fifo(NXP_UART_STATE *s)
 {
     s->read_count = 0;
     s->read_pos = 0;
 
     /* Reset FIFO flags */
     s->flags &= ~NXP_UART_FLAG_RXFF;
     s->flags |= NXP_UART_FLAG_RXFE;
 }
 
 static inline void nxp_uart_reset_tx_fifo(NXP_UART_STATE *s)
 {
     /* Reset FIFO flags */
     s->flags &= ~NXP_UART_FLAG_TXFF;
     s->flags |= NXP_UART_FLAG_TXFE;
 }
 
 static void nxp_uart_fifo_rx_put(void *opaque, uint32_t value)
 {
     NXP_UART_STATE *s = (NXP_UART_STATE *)opaque;
     int slot;
     unsigned pipe_depth;
 
     pipe_depth = nxp_uart_get_fifo_depth(s);
     slot = (s->read_pos + s->read_count) & (pipe_depth - 1);
     s->read_fifo[slot] = value;
     s->read_count++;
     s->flags &= ~NXP_UART_FLAG_RXFE;
     trace_nxp_uart_fifo_rx_put(value, s->read_count, pipe_depth);
     if (s->read_count == pipe_depth) {
         trace_nxp_uart_fifo_rx_full();
         s->flags |= NXP_UART_FLAG_RXFF;
     }
     if (s->read_count == s->read_trigger) {
         s->int_level |= INT_RX;
         nxp_uart_update(s);
     }
 }
 
 static void nxp_uart_loopback_tx(NXP_UART_STATE *s, uint32_t value)
 {
     if (!nxp_uart_loopback_enabled(s)) {
         return;
     }
 
     /*
      * Caveat:
      *
      * In real hardware, TX loopback happens at the serial-bit level
      * and then reassembled by the RX logics back into bytes and placed
      * into the RX fifo. That is, loopback happens after TX fifo.
      *
      * Because the real hardware TX fifo is time-drained at the frame
      * rate governed by the configured serial format, some loopback
      * bytes in TX fifo may still be able to get into the RX fifo
      * that could be full at times while being drained at software
      * pace.
      *
      * In such scenario, the RX draining pace is the major factor
      * deciding which loopback bytes get into the RX fifo, unless
      * hardware flow-control is enabled.
      *
      * For simplicity, the above described is not emulated.
      */
     nxp_uart_fifo_rx_put(s, value);
 }
 
 static void nxp_uart_write_txdata(NXP_UART_STATE *s, uint8_t data)
 {
     if (!(s->cr & CR_UARTEN)) {
         qemu_log_mask(LOG_GUEST_ERROR,
                       "NXP_UART data written to disabled UART\n");
     }
     if (!(s->cr & CR_TXE)) {
         qemu_log_mask(LOG_GUEST_ERROR,
                       "NXP_UART data written to disabled TX UART\n");
     }
 
     /*
      * XXX this blocks entire thread. Rewrite to use
      * qemu_chr_fe_write and background I/O callbacks
      */
     qemu_chr_fe_write_all(&s->chr, &data, 1);
     nxp_uart_loopback_tx(s, data);
     s->int_level |= INT_TX;
     nxp_uart_update(s);
 }
 
 static uint32_t nxp_uart_read_rxdata(NXP_UART_STATE *s)
 {
     uint32_t c;
     unsigned fifo_depth = nxp_uart_get_fifo_depth(s);
 
     s->flags &= ~NXP_UART_FLAG_RXFF;
     c = s->read_fifo[s->read_pos];
     if (s->read_count > 0) {
         s->read_count--;
         s->read_pos = (s->read_pos + 1) & (fifo_depth - 1);
     }
     if (s->read_count == 0) {
         s->flags |= NXP_UART_FLAG_RXFE;
     }
     if (s->read_count == s->read_trigger - 1) {
         s->int_level &= ~INT_RX;
     }
     trace_nxp_uart_read_fifo(s->read_count, fifo_depth);
     s->rsr = c >> 8;
     nxp_uart_update(s);
     qemu_chr_fe_accept_input(&s->chr);
     return c;
 }
 
 static uint64_t nxp_uart_read(void *opaque, hwaddr offset,
                            unsigned size)
 {
     NXP_UART_STATE *s = (NXP_UART_STATE *)opaque;
     uint64_t r;
 
     switch (offset >> 2) {
     case 0: /* UARTDR */
         r = nxp_uart_read_rxdata(s);
         break;
     case 1: /* UARTRSR */
         r = s->rsr;
         break;
     case 6: /* UARTFR */
         r = s->flags;
         break;
     case 8: /* UARTILPR */
         r = s->ilpr;
         break;
     case 9: /* UARTIBRD */
         r = s->ibrd;
         break;
     case 10: /* UARTFBRD */
         r = s->fbrd;
         break;
     case 11: /* UARTLCR_H */
         r = s->lcr;
         break;
     case 12: /* UARTCR */
         r = s->cr;
         break;
     case 13: /* UARTIFLS */
         r = s->ifl;
         break;
     case 14: /* UARTIMSC */
         r = s->int_enabled;
         break;
     case 15: /* UARTRIS */
         r = s->int_level;
         break;
     case 16: /* UARTMIS */
         r = s->int_level & s->int_enabled;
         break;
     case 18: /* UARTDMACR */
         r = s->dmacr;
         break;
     case 0x3f8 ... 0x400:
         r = s->id[(offset - 0xfe0) >> 2];
         break;
     default:
         qemu_log_mask(LOG_GUEST_ERROR,
                       "nxp_uart_read: Bad offset 0x%x\n", (int)offset);
         r = 0;
         break;
     }
 
     trace_nxp_uart_read(offset, r, nxp_uart_regname(offset));
     return r;
 }
 
 static void nxp_uart_set_read_trigger(NXP_UART_STATE *s)
 {
 #if 0
     /* The docs say the RX interrupt is triggered when the FIFO exceeds
        the threshold.  However linux only reads the FIFO in response to an
        interrupt.  Triggering the interrupt when the FIFO is non-empty seems
        to make things work.  */
     if (s->lcr & LCR_FEN)
         s->read_trigger = (s->ifl >> 1) & 0x1c;
     else
 #endif
         s->read_trigger = 1;
 }
 
 static unsigned int nxp_uart_get_baudrate(const NXP_UART_STATE *s)
 {
     uint64_t clk;
 
     if (s->ibrd == 0) {
         return 0;
     }
 
     clk = clock_get_hz(s->clk);
     return (clk / ((s->ibrd << 6) + s->fbrd)) << 2;
 }
 
 static void nxp_uart_trace_baudrate_change(const NXP_UART_STATE *s)
 {
     trace_nxp_uart_baudrate_change(nxp_uart_get_baudrate(s),
                                 clock_get_hz(s->clk),
                                 s->ibrd, s->fbrd);
 }
 
 static void nxp_uart_loopback_mdmctrl(NXP_UART_STATE *s)
 {
     uint32_t cr, fr, il;
 
     if (!nxp_uart_loopback_enabled(s)) {
         return;
     }
 
     /*
      * Loopback software-driven modem control outputs to modem status inputs:
      *   FR.RI  <= CR.Out2
      *   FR.DCD <= CR.Out1
      *   FR.CTS <= CR.RTS
      *   FR.DSR <= CR.DTR
      *
      * The loopback happens immediately even if this call is triggered
      * by setting only CR.LBE.
      *
      * CTS/RTS updates due to enabled hardware flow controls are not
      * dealt with here.
      */
     cr = s->cr;
     fr = s->flags & ~(NXP_UART_FLAG_RI | NXP_UART_FLAG_DCD |
                       NXP_UART_FLAG_DSR | NXP_UART_FLAG_CTS);
     fr |= (cr & CR_OUT2) ? NXP_UART_FLAG_RI  : 0;
     fr |= (cr & CR_OUT1) ? NXP_UART_FLAG_DCD : 0;
     fr |= (cr & CR_RTS)  ? NXP_UART_FLAG_CTS : 0;
     fr |= (cr & CR_DTR)  ? NXP_UART_FLAG_DSR : 0;
 
     /* Change interrupts based on updated FR */
     il = s->int_level & ~(INT_DSR | INT_DCD | INT_CTS | INT_RI);
     il |= (fr & NXP_UART_FLAG_DSR) ? INT_DSR : 0;
     il |= (fr & NXP_UART_FLAG_DCD) ? INT_DCD : 0;
     il |= (fr & NXP_UART_FLAG_CTS) ? INT_CTS : 0;
     il |= (fr & NXP_UART_FLAG_RI)  ? INT_RI  : 0;
 
     s->flags = fr;
     s->int_level = il;
     nxp_uart_update(s);
 }
 
 static void nxp_uart_loopback_break(NXP_UART_STATE *s, int brk_enable)
 {
     if (brk_enable) {
         nxp_uart_loopback_tx(s, DR_BE);
     }
 }
 
 static void nxp_uart_write(void *opaque, hwaddr offset,
                         uint64_t value, unsigned size)
 {
     NXP_UART_STATE *s = (NXP_UART_STATE *)opaque;
     unsigned char ch;
 
     trace_nxp_uart_write(offset, value, nxp_uart_regname(offset));
 
     switch (offset >> 2) {
     case 0: /* UARTDR */
         ch = value;
         nxp_uart_write_txdata(s, ch);
         break;
     case 1: /* UARTRSR/UARTECR */
         s->rsr = 0;
         break;
     case 6: /* UARTFR */
         /* Writes to Flag register are ignored.  */
         break;
     case 8: /* UARTILPR */
         s->ilpr = value;
         break;
     case 9: /* UARTIBRD */
         s->ibrd = value & IBRD_MASK;
         nxp_uart_trace_baudrate_change(s);
         break;
     case 10: /* UARTFBRD */
         s->fbrd = value & FBRD_MASK;
         nxp_uart_trace_baudrate_change(s);
         break;
     case 11: /* UARTLCR_H */
         /* Reset the FIFO state on FIFO enable or disable */
         if ((s->lcr ^ value) & LCR_FEN) {
             nxp_uart_reset_rx_fifo(s);
             nxp_uart_reset_tx_fifo(s);
         }
         if ((s->lcr ^ value) & LCR_BRK) {
             int break_enable = value & LCR_BRK;
             qemu_chr_fe_ioctl(&s->chr, CHR_IOCTL_SERIAL_SET_BREAK,
                               &break_enable);
             nxp_uart_loopback_break(s, break_enable);
         }
         s->lcr = value;
         nxp_uart_set_read_trigger(s);
         break;
     case 12: /* UARTCR */
         /* ??? Need to implement the enable bit.  */
         s->cr = value;
         nxp_uart_loopback_mdmctrl(s);
         break;
     case 13: /* UARTIFS */
         s->ifl = value;
         nxp_uart_set_read_trigger(s);
         break;
     case 14: /* UARTIMSC */
         s->int_enabled = value;
         nxp_uart_update(s);
         break;
     case 17: /* UARTICR */
         s->int_level &= ~value;
         nxp_uart_update(s);
         break;
     case 18: /* UARTDMACR */
         s->dmacr = value;
         if (value & 3) {
             qemu_log_mask(LOG_UNIMP, "nxp_uart: DMA not implemented\n");
         }
         break;
     default:
         qemu_log_mask(LOG_GUEST_ERROR,
                       "nxp_uart_write: Bad offset 0x%x\n", (int)offset);
     }
 }
 
 static int nxp_uart_can_receive(void *opaque)
 {
     NXP_UART_STATE *s = (NXP_UART_STATE *)opaque;
     unsigned fifo_depth = nxp_uart_get_fifo_depth(s);
     unsigned fifo_available = fifo_depth - s->read_count;
 
     /*
      * In theory we should check the UART and RX enable bits here and
      * return 0 if they are not set (so the guest can't receive data
      * until you have enabled the UART). In practice we suspect there
      * is at least some guest code out there which has been tested only
      * on QEMU and which never bothers to enable the UART because we
      * historically never enforced that. So we effectively keep the
      * UART continuously enabled regardless of the enable bits.
      */
 
     trace_nxp_uart_can_receive(s->lcr, s->read_count, fifo_depth, fifo_available);
     return fifo_available;
 }
 
 static void nxp_uart_receive(void *opaque, const uint8_t *buf, int size)
 {
     trace_nxp_uart_receive(size);
     /*
      * In loopback mode, the RX input signal is internally disconnected
      * from the entire receiving logics; thus, all inputs are ignored,
      * and BREAK detection on RX input signal is also not performed.
      */
     if (nxp_uart_loopback_enabled(opaque)) {
         return;
     }
 
     for (int i = 0; i < size; i++) {
         nxp_uart_fifo_rx_put(opaque, buf[i]);
     }
 }
 
 static void nxp_uart_event(void *opaque, QEMUChrEvent event)
 {
     if (event == CHR_EVENT_BREAK && !nxp_uart_loopback_enabled(opaque)) {
         nxp_uart_fifo_rx_put(opaque, DR_BE);
     }
 }
 
 static void nxp_uart_clock_update(void *opaque, ClockEvent event)
 {
     NXP_UART_STATE *s = NXP_UART(opaque);
 
     nxp_uart_trace_baudrate_change(s);
 }
 
 static const MemoryRegionOps nxp_uart_ops = {
     .read = nxp_uart_read,
     .write = nxp_uart_write,
     .endianness = DEVICE_NATIVE_ENDIAN,
     .impl.min_access_size = 4,
     .impl.max_access_size = 4,
 };
 
 static bool nxp_uart_clock_needed(void *opaque)
 {
     NXP_UART_STATE *s = NXP_UART(opaque);
 
     return s->migrate_clk;
 }
 
 static const VMStateDescription vmstate_nxp_uart_clock = {
     .name = "nxp_uart/clock",
     .version_id = 1,
     .minimum_version_id = 1,
     .needed = nxp_uart_clock_needed,
     .fields = (const VMStateField[]) {
         VMSTATE_CLOCK(clk, NXP_UART_STATE),
         VMSTATE_END_OF_LIST()
     }
 };
 
 static int nxp_uart_post_load(void *opaque, int version_id)
 {
     NXP_UART_STATE* s = opaque;
 
     /* Sanity-check input state */
     if (s->read_pos >= ARRAY_SIZE(s->read_fifo) ||
         s->read_count > ARRAY_SIZE(s->read_fifo)) {
         return -1;
     }
 
     if (!nxp_uart_is_fifo_enabled(s) && s->read_count > 0 && s->read_pos > 0) {
         /*
          * Older versions of NXP_UART didn't ensure that the single
          * character in the FIFO in FIFO-disabled mode is in
          * element 0 of the array; convert to follow the current
          * code's assumptions.
          */
         s->read_fifo[0] = s->read_fifo[s->read_pos];
         s->read_pos = 0;
     }
 
     s->ibrd &= IBRD_MASK;
     s->fbrd &= FBRD_MASK;
 
     return 0;
 }
 
 static const VMStateDescription vmstate_nxp_uart = {
     .name = "nxp_uart",
     .version_id = 2,
     .minimum_version_id = 2,
     .post_load = nxp_uart_post_load,
     .fields = (const VMStateField[]) {
         VMSTATE_UNUSED(sizeof(uint32_t)),
         VMSTATE_UINT32(flags, NXP_UART_STATE),
         VMSTATE_UINT32(lcr, NXP_UART_STATE),
         VMSTATE_UINT32(rsr, NXP_UART_STATE),
         VMSTATE_UINT32(cr, NXP_UART_STATE),
         VMSTATE_UINT32(dmacr, NXP_UART_STATE),
         VMSTATE_UINT32(int_enabled, NXP_UART_STATE),
         VMSTATE_UINT32(int_level, NXP_UART_STATE),
         VMSTATE_UINT32_ARRAY(read_fifo, NXP_UART_STATE, NXP_UART_FIFO_DEPTH),
         VMSTATE_UINT32(ilpr, NXP_UART_STATE),
         VMSTATE_UINT32(ibrd, NXP_UART_STATE),
         VMSTATE_UINT32(fbrd, NXP_UART_STATE),
         VMSTATE_UINT32(ifl, NXP_UART_STATE),
         VMSTATE_INT32(read_pos, NXP_UART_STATE),
         VMSTATE_INT32(read_count, NXP_UART_STATE),
         VMSTATE_INT32(read_trigger, NXP_UART_STATE),
         VMSTATE_END_OF_LIST()
     },
     .subsections = (const VMStateDescription * const []) {
         &vmstate_nxp_uart_clock,
         NULL
     }
 };
 
 static const Property nxp_uart_properties[] = {
     DEFINE_PROP_CHR("chardev", NXP_UART_STATE, chr),
     DEFINE_PROP_BOOL("migrate-clk", NXP_UART_STATE, migrate_clk, true),
 };
 
 static void nxp_uart_init(Object *obj)
 {
     SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
     NXP_UART_STATE *s = NXP_UART(obj);
     int i;
 
     memory_region_init_io(&s->iomem, OBJECT(s), &nxp_uart_ops, s, "nxp_uart", 0x1000);
     sysbus_init_mmio(sbd, &s->iomem);
     for (i = 0; i < ARRAY_SIZE(s->irq); i++) {
         sysbus_init_irq(sbd, &s->irq[i]);
     }
 
     s->clk = qdev_init_clock_in(DEVICE(obj), "clk", nxp_uart_clock_update, s,
                                 ClockUpdate);
 
     s->id = nxp_uart_id_arm;
 }
 
 static void nxp_uart_realize(DeviceState *dev, Error **errp)
 {
     NXP_UART_STATE *s = NXP_UART(dev);
 
     qemu_chr_fe_set_handlers(&s->chr, nxp_uart_can_receive, nxp_uart_receive,
                              nxp_uart_event, NULL, s, NULL, true);
 }
 
 static void nxp_uart_reset(DeviceState *dev)
 {
     NXP_UART_STATE *s = NXP_UART(dev);
 
     s->lcr = 0;
     s->rsr = 0;
     s->dmacr = 0;
     s->int_enabled = 0;
     s->int_level = 0;
     s->ilpr = 0;
     s->ibrd = 0;
     s->fbrd = 0;
     s->read_trigger = 1;
     s->ifl = 0x12;
     s->cr = 0x300;
     s->flags = 0;
     nxp_uart_reset_rx_fifo(s);
     nxp_uart_reset_tx_fifo(s);
 }
 
 static void nxp_uart_class_init(ObjectClass *oc, void *data)
 {
     DeviceClass *dc = DEVICE_CLASS(oc);
 
     dc->realize = nxp_uart_realize;
     device_class_set_legacy_reset(dc, nxp_uart_reset);
     dc->vmsd = &vmstate_nxp_uart;
     device_class_set_props(dc, nxp_uart_properties);
 }
 
 static const TypeInfo nxp_uart_arm_info = {
     .name          = TYPE_NXP_UART,
     .parent        = TYPE_SYS_BUS_DEVICE,
     .instance_size = sizeof(NXP_UART_STATE),
     .instance_init = nxp_uart_init,
     .class_init    = nxp_uart_class_init,
 };
 
 static void nxp_uart_register_types(void)
 {
     type_register_static(&nxp_uart_arm_info);
 }
 
 type_init(nxp_uart_register_types)
 