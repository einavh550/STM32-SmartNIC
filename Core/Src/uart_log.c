/**
 * uart_log.c - non-blocking printf over USART3. See uart_log.h.
 *
 * One producer (main loop, through printf -> _write) and one consumer (the
 * USART3 interrupt), like ring_buffer.c but for bytes:
 *   head  only written by the producer: where the next byte goes
 *   tail  only written by the interrupt: next byte to send
 * Both only grow; (head - tail) is the number of bytes waiting, and stays
 * correct when the 32-bit counters wrap. The size is a power of 2, so
 * "index & MASK" replaces "index % SIZE".
 */
#include "uart_log.h"
#include "stm32h7xx_hal.h"

_Static_assert((UART_LOG_BUF_SIZE & (UART_LOG_BUF_SIZE - 1u)) == 0u,
               "UART_LOG_BUF_SIZE must be a power of 2");

#define MASK            (UART_LOG_BUF_SIZE - 1u)
#define LOG_UART        USART3
#define LOG_UART_IRQn   USART3_IRQn
#define LOG_UART_PRIO   (5u)   /* below ETH (0): frames always come first */

static uint8_t buf[UART_LOG_BUF_SIZE];
static volatile uint32_t head;      /* producer (main) */
static volatile uint32_t tail;      /* consumer (USART3 ISR) */
static uint32_t dropped;            /* main only */

void uart_log_init(void)
{
    HAL_NVIC_SetPriority(LOG_UART_IRQn, LOG_UART_PRIO, 0u);
    HAL_NVIC_EnableIRQ(LOG_UART_IRQn);
}

uint32_t uart_log_dropped(void)
{
    return dropped;
}

/* Turn the "transmit register empty" interrupt on. CR1 is also written by
 * the ISR (it turns the interrupt off when the ring is empty), and setting a
 * bit is a read-modify-write, so keep the USART3 interrupt out meanwhile.
 * Only USART3 is masked: the ETH interrupt is never delayed. */
static void start_tx(void)
{
    HAL_NVIC_DisableIRQ(LOG_UART_IRQn);
    SET_BIT(LOG_UART->CR1, USART_CR1_TXEIE_TXFNFIE);
    HAL_NVIC_EnableIRQ(LOG_UART_IRQn);
}

/* newlib's printf ends up here (overrides the weak _write in syscalls.c). */
int _write(int file, char *ptr, int len)
{
    (void)file;

    uint32_t n    = (uint32_t)len;
    uint32_t h    = head;
    uint32_t room = UART_LOG_BUF_SIZE - (h - tail);

    if (n > room)
    {
        dropped += n;       /* no room for the whole text: drop all of it */
        return len;         /* report it as written, or printf would retry */
    }

    for (uint32_t i = 0u; i < n; i++)
    {
        buf[(h + i) & MASK] = (uint8_t)ptr[i];
    }
    __DMB();                /* the bytes are in RAM before the ISR can see them */
    head = h + n;

    start_tx();
    return len;
}

/* One byte per interrupt: TDR is free again ~87 us after the last write. */
void USART3_IRQHandler(void)
{
    if (((LOG_UART->ISR & USART_ISR_TXE_TXFNF) != 0u) &&
        ((LOG_UART->CR1 & USART_CR1_TXEIE_TXFNFIE) != 0u))
    {
        uint32_t t = tail;
        if (t != head)
        {
            LOG_UART->TDR = buf[t & MASK];
            tail = t + 1u;
        }
        else
        {
            /* Nothing left: stop, or this interrupt would fire forever. */
            CLEAR_BIT(LOG_UART->CR1, USART_CR1_TXEIE_TXFNFIE);
        }
    }
}
