/**
 * uart_log.h - non-blocking printf over the ST-LINK COM port (USART3).
 *
 * Before: printf -> _write -> __io_putchar -> HAL_UART_Transmit(), which
 * waits for every character to leave the wire: 87 us per character at
 * 115200 baud, ~50 ms for one stats print. The main loop processed no frames
 * meanwhile, the 16 RX buffers filled up and frames were dropped (stress
 * run 1 and 2).
 *
 * Now: _write only copies the text into a RAM ring buffer and returns at
 * once. The USART3 "transmit register empty" interrupt sends the bytes in
 * the background, one per interrupt. The main loop never waits for the UART.
 *
 * If the ring has no room for a whole write, that write is dropped (not
 * cut in half) and counted: losing log text is better than losing frames.
 */
#ifndef UART_LOG_H
#define UART_LOG_H

#include <stdint.h>

#define UART_LOG_BUF_SIZE   (4096u)   /* power of 2; holds ~7 stats prints */

/** Start interrupt-driven output. Call once, right after BSP_COM_Init(). */
void uart_log_init(void);

/** Bytes of log text dropped because the ring was full, since boot. */
uint32_t uart_log_dropped(void);

#endif /* UART_LOG_H */
