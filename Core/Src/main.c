/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "string.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include "ring_buffer_test.h"
#include "eth_rx.h"
#include "pkt_parse.h"
#include "pkt_filter.h"
#include "filter_policy.h"
#include "perf.h"
#include "uart_log.h"
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */
#define STATS_PERIOD_MS   (5000u)   /* how often the filter counters are printed */
#define BUTTON_DEBOUNCE_MS (200u)   /* ignore button bounces closer than this */
/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
#if defined ( __ICCARM__ ) /*!< IAR Compiler */
#pragma location=0x30000000
ETH_DMADescTypeDef  DMARxDscrTab[ETH_RX_DESC_CNT]; /* Ethernet Rx DMA Descriptors */
#pragma location=0x30000080
ETH_DMADescTypeDef  DMATxDscrTab[ETH_TX_DESC_CNT]; /* Ethernet Tx DMA Descriptors */

#elif defined ( __CC_ARM )  /* MDK ARM Compiler */

__attribute__((at(0x30000000))) ETH_DMADescTypeDef  DMARxDscrTab[ETH_RX_DESC_CNT]; /* Ethernet Rx DMA Descriptors */
__attribute__((at(0x30000080))) ETH_DMADescTypeDef  DMATxDscrTab[ETH_TX_DESC_CNT]; /* Ethernet Tx DMA Descriptors */

#elif defined ( __GNUC__ ) /* GNU Compiler */

ETH_DMADescTypeDef DMARxDscrTab[ETH_RX_DESC_CNT] __attribute__((section(".RxDescripSection"))); /* Ethernet Rx DMA Descriptors */
ETH_DMADescTypeDef DMATxDscrTab[ETH_TX_DESC_CNT] __attribute__((section(".TxDescripSection")));   /* Ethernet Tx DMA Descriptors */
#endif

ETH_TxPacketConfig TxConfig;

COM_InitTypeDef BspCOMInit;

ETH_HandleTypeDef heth;

/* USER CODE BEGIN PV */
/* Rule table (filter_policy.c) + counters. Used only by the main loop. */
static pkt_filter_t filter;

/* Per-frame log switch. printf at 115200 costs ~7 ms per line, far more than
 * the filter itself, so it must be off when measuring. The USER button toggles
 * it at runtime; the stats line every STATS_PERIOD_MS is always printed.
 * The ISR only raises a flag; the main loop does the toggle and the printing. */
static volatile uint8_t button_pressed;   /* set by the button ISR, cleared by main */
static uint8_t log_frames = 1u;           /* 1 = print one line per frame (yellow LED on) */

/* CPU cycles spent in pkt_filter_process() per frame (parse + all filter
 * stages), collected over one stats period and printed with the stats. */
static perf_stats_t filter_cycles;

/* The same cost split by the path the frame took through the filter, since
 * boot (never reset), so each scenario's frame types can be told apart:
 *   path_reason[r]  dropped before any rule matched (malformed, bad-checksum,
 *                   spoofed, tcp-scan) or by the default action
 *   path_pass[i]    matched rule i and passed
 *   path_limit[i]   matched rule i and was dropped by its rate limit       */
static perf_stats_t path_reason[DROP_REASON_COUNT];
static perf_stats_t path_pass[POLICY_RULE_COUNT];
static perf_stats_t path_limit[POLICY_RULE_COUNT];
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MPU_Config(void);
static void MX_GPIO_Init(void);
static void MX_ETH_Init(void);
/* USER CODE BEGIN PFP */
static void log_frame(const pkt_desc_t *pkt, const pkt_hdr_t *hdr, pkt_verdict_t v);
static void print_stats(void);
static void handle_button(void);
static void record_path(pkt_verdict_t v, uint32_t cycles);
static void print_paths(void);
/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MPU Configuration--------------------------------------------------------*/
  MPU_Config();

  /* Enable the CPU Cache */

  /* Enable I-Cache---------------------------------------------------------*/
  SCB_EnableICache();

  /* Enable D-Cache---------------------------------------------------------*/
  SCB_EnableDCache();

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_ETH_Init();
  /* USER CODE BEGIN 2 */

  /* USER CODE END 2 */

  /* Initialize leds */
  BSP_LED_Init(LED_GREEN);
  BSP_LED_Init(LED_YELLOW);
  BSP_LED_Init(LED_RED);

  /* Initialize USER push-button, will be used to trigger an interrupt each time it's pressed.*/
  BSP_PB_Init(BUTTON_USER, BUTTON_MODE_EXTI);

  /* Initialize COM1 port (115200, 8 bits (7-bit data + 1 stop bit), no parity */
  BspCOMInit.BaudRate   = 115200;
  BspCOMInit.WordLength = COM_WORDLENGTH_8B;
  BspCOMInit.StopBits   = COM_STOPBITS_1;
  BspCOMInit.Parity     = COM_PARITY_NONE;
  BspCOMInit.HwFlowCtl  = COM_HWCONTROL_NONE;
  if (BSP_COM_Init(COM1, &BspCOMInit) != BSP_ERROR_NONE)
  {
    Error_Handler();
  }

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  /* From here printf only queues text; the USART3 interrupt sends it
   * (uart_log.c). COM1 (USART3) was just set up by BSP_COM_Init() above. */
  uart_log_init();

#ifdef RB_SELF_TEST
  BSP_LED_On((rb_self_test() == 0u) ? LED_GREEN : LED_RED);
#endif

  /* Start Ethernet RX. Done here (not in USER CODE 2) so the COM port is
   * already up and printf works. Order matters:
   * 1. eth_rx_init() fills the free list,
   * 2. HAL_ETH_Start_IT() takes 4 buffers for the descriptors (via
   *    HAL_ETH_RxAllocateCallback) and enables the ETH DMA interrupts. */
  if (!pkt_filter_init(&filter, filter_policy, POLICY_RULE_COUNT, POLICY_DEFAULT_ACTION))
  {
    printf("Invalid filter policy\r\n");
    Error_Handler();
  }

  /* Checksum offload: the MAC checks every IPv4 header and TCP/UDP checksum
   * in hardware and reports the result in the RX descriptor. The HAL default
   * (DropTCPIPChecksumErrorPacket = ENABLE) also DROPS the failing frames
   * inside the MAC, before the DMA, without any counter: the firmware never
   * learns they existed. Forward them instead; eth_rx.c passes the MAC's
   * report on with each frame and the filter drops and counts them as
   * "bad-checksum". The MAC config can only change before HAL_ETH_Start_IT(). */
  {
    ETH_MACConfigTypeDef mac_cfg;
    HAL_ETH_GetMACConfig(&heth, &mac_cfg);
    mac_cfg.DropTCPIPChecksumErrorPacket = DISABLE;
    if (HAL_ETH_SetMACConfig(&heth, &mac_cfg) != HAL_OK)
    {
      printf("ETH MAC config failed\r\n");
      Error_Handler();
    }
  }

  eth_rx_init();
  if (HAL_ETH_Start_IT(&heth) != HAL_OK)
  {
    printf("ETH start failed\r\n");
    Error_Handler();
  }
  printf("ETH RX started\r\n");
  /* Read back from the RCC registers: proves the PLL really runs (550 MHz). */
  printf("CPU clock: %lu MHz\r\n", (unsigned long)(HAL_RCC_GetSysClockFreq() / 1000000u));
  perf_init();
  perf_reset(&filter_cycles);
  for (uint32_t i = 0u; i < DROP_REASON_COUNT; i++)
  {
    perf_reset(&path_reason[i]);
  }
  for (uint32_t i = 0u; i < POLICY_RULE_COUNT; i++)
  {
    perf_reset(&path_pass[i]);
    perf_reset(&path_limit[i]);
  }
  printf("DWT cycle counter on, measurement overhead %lu cycles\r\n",
         (unsigned long)perf_overhead());
  printf("Per-frame log ON (USER button toggles)\r\n");
  BSP_LED_On(LED_YELLOW);

  while (1)
  {

    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
    static uint32_t last_stats_ms;
    pkt_desc_t pkt;
    pkt_hdr_t  hdr;

    /* Consumer side: take every frame the ISR queued, then give the buffer back. */
    while (eth_rx_pop(&pkt))
    {
      /* Parse, drop if malformed or the MAC reported a checksum error, else
       * run the rules. Counters are updated inside. HAL_GetTick() is read
       * before the timer starts so only the filter itself is measured. */
      uint32_t now_ms = HAL_GetTick();
      uint32_t t0 = perf_now();
      /* PERF_PIN (PA5, D13) is HIGH while the filter runs: a logic analyzer
       * measures the pulse width from outside, to cross-check the DWT number.
       * BSRR is written directly (one store, set = low 16 bits, reset = high
       * 16 bits) instead of HAL_GPIO_WritePin(), so the pin edges add almost
       * nothing to what is measured. */
      PERF_PIN_GPIO_Port->BSRR = PERF_PIN_Pin;
      pkt_verdict_t v = pkt_filter_process(&filter, pkt.data, pkt.len, pkt.flags,
                                           now_ms, &hdr);
      PERF_PIN_GPIO_Port->BSRR = (uint32_t)PERF_PIN_Pin << 16;
      uint32_t cycles = perf_now() - t0;
      perf_record(&filter_cycles, cycles);
      record_path(v, cycles);

      if (log_frames != 0u)
      {
        log_frame(&pkt, &hdr, v);
      }

      /* Always give the buffer back, even for a dropped frame, or the pool leaks. */
      eth_rx_buf_free(pkt.data);
    }

    /* Buffers were just freed: hand them to any RX descriptor left without
     * one, and wake the DMA if it stopped (see eth_rx_refill()). */
    eth_rx_refill();

    handle_button();
    eth_rx_poll_hw();   /* collect the MAC's clear-on-read drop counters */

    /* Unsigned subtraction stays correct when HAL_GetTick() wraps at 2^32. */
    if ((HAL_GetTick() - last_stats_ms) >= STATS_PERIOD_MS)
    {
      last_stats_ms = HAL_GetTick();
      print_stats();
    }
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Supply configuration update enable
  */
  HAL_PWREx_ConfigSupply(PWR_LDO_SUPPLY);

  /** Configure the main internal regulator output voltage
  */
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE0);

  while(!__HAL_PWR_GET_FLAG(PWR_FLAG_VOSRDY)) {}

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 4;
  RCC_OscInitStruct.PLL.PLLN = 275;
  RCC_OscInitStruct.PLL.PLLP = 1;
  RCC_OscInitStruct.PLL.PLLQ = 4;
  RCC_OscInitStruct.PLL.PLLR = 2;
  RCC_OscInitStruct.PLL.PLLRGE = RCC_PLL1VCIRANGE_1;
  RCC_OscInitStruct.PLL.PLLVCOSEL = RCC_PLL1VCOWIDE;
  RCC_OscInitStruct.PLL.PLLFRACN = 0;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2
                              |RCC_CLOCKTYPE_D3PCLK1|RCC_CLOCKTYPE_D1PCLK1;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.SYSCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB3CLKDivider = RCC_APB3_DIV2;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_APB1_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_APB2_DIV2;
  RCC_ClkInitStruct.APB4CLKDivider = RCC_APB4_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_3) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief ETH Initialization Function
  * @param None
  * @retval None
  */
static void MX_ETH_Init(void)
{

  /* USER CODE BEGIN ETH_Init 0 */

  /* USER CODE END ETH_Init 0 */

   static uint8_t MACAddr[6];

  /* USER CODE BEGIN ETH_Init 1 */

  /* USER CODE END ETH_Init 1 */
  heth.Instance = ETH;
  MACAddr[0] = 0x00;
  MACAddr[1] = 0x80;
  MACAddr[2] = 0xE1;
  MACAddr[3] = 0x00;
  MACAddr[4] = 0x00;
  MACAddr[5] = 0x00;
  heth.Init.MACAddr = &MACAddr[0];
  heth.Init.MediaInterface = HAL_ETH_RMII_MODE;
  heth.Init.TxDesc = DMATxDscrTab;
  heth.Init.RxDesc = DMARxDscrTab;
  heth.Init.RxBuffLen = 1536;

  /* USER CODE BEGIN MACADDRESS */

  /* USER CODE END MACADDRESS */

  if (HAL_ETH_Init(&heth) != HAL_OK)
  {
    Error_Handler();
  }

  memset(&TxConfig, 0 , sizeof(ETH_TxPacketConfig));
  TxConfig.Attributes = ETH_TX_PACKETS_FEATURES_CSUM | ETH_TX_PACKETS_FEATURES_CRCPAD;
  TxConfig.ChecksumCtrl = ETH_CHECKSUM_IPHDR_PAYLOAD_INSERT_PHDR_CALC;
  TxConfig.CRCPadCtrl = ETH_CRC_PAD_INSERT;
  /* USER CODE BEGIN ETH_Init 2 */

  /* USER CODE END ETH_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();

  /*Configure GPIO pin Output Level */
  HAL_GPIO_WritePin(PERF_PIN_GPIO_Port, PERF_PIN_Pin, GPIO_PIN_RESET);

  /*Configure GPIO pin : PERF_PIN_Pin */
  GPIO_InitStruct.Pin = PERF_PIN_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
  HAL_GPIO_Init(PERF_PIN_GPIO_Port, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */
/** USER button ISR (overrides the weak BSP version). Keep it tiny: just a flag. */
void BSP_PB_Callback(Button_TypeDef Button)
{
  if (Button == BUTTON_USER)
  {
    button_pressed = 1u;
  }
}

/** Main-loop side of the button: debounce, flip the log switch, report it. */
static void handle_button(void)
{
  static uint32_t last_press_ms;

  if (button_pressed == 0u)
  {
    return;
  }
  button_pressed = 0u;

  /* A mechanical button bounces: one press can fire several interrupts. */
  if ((HAL_GetTick() - last_press_ms) < BUTTON_DEBOUNCE_MS)
  {
    return;
  }
  last_press_ms = HAL_GetTick();

  log_frames ^= 1u;
  if (log_frames != 0u)
  {
    BSP_LED_On(LED_YELLOW);
  }
  else
  {
    BSP_LED_Off(LED_YELLOW);
  }
  printf("Per-frame log %s\r\n", (log_frames != 0u) ? "ON" : "OFF");
}

/** Print one line per frame: what it is and what the filter decided. */
static void log_frame(const pkt_desc_t *pkt, const pkt_hdr_t *hdr, pkt_verdict_t v)
{
  printf("RX %4u  ", (unsigned)pkt->len);

  if ((hdr->valid & PKT_HAS_IPV4) != 0u)
  {
    printf("IPv4 %u.%u.%u.%u -> %u.%u.%u.%u p%u",
           (unsigned)(hdr->src_ip >> 24), (unsigned)((hdr->src_ip >> 16) & 0xFFu),
           (unsigned)((hdr->src_ip >> 8) & 0xFFu), (unsigned)(hdr->src_ip & 0xFFu),
           (unsigned)(hdr->dst_ip >> 24), (unsigned)((hdr->dst_ip >> 16) & 0xFFu),
           (unsigned)((hdr->dst_ip >> 8) & 0xFFu), (unsigned)(hdr->dst_ip & 0xFFu),
           (unsigned)hdr->ip_proto);

    if ((hdr->valid & PKT_HAS_L4) != 0u)
    {
      printf(" %u->%u", (unsigned)hdr->src_port, (unsigned)hdr->dst_port);

      if (hdr->ip_proto == IP_PROTO_TCP)
      {
        printf(" flags 0x%02X", (unsigned)hdr->tcp_flags);
      }
    }
  }
  else if ((hdr->valid & PKT_HAS_ETH) != 0u)
  {
    printf("type 0x%04X", (unsigned)hdr->ethertype);
  }
  else
  {
    printf("too short");
  }

  /* The MAC's checksum offload report (eth_rx.c), if it found an error. */
  if ((pkt->flags & PKT_FLAG_IP_HDR_ERR) != 0u)
  {
    printf("  [hw: ip-hdr]");
  }
  if ((pkt->flags & PKT_FLAG_IP_PAYLOAD_ERR) != 0u)
  {
    printf("  [hw: payload]");
  }

  const char *verdict = (v.action == PKT_PASS) ? "PASS" : "DROP";

  if (v.rule_idx >= 0)
  {
    /* A rate-limit drop also has a rule: say which rule and why. */
    printf("  => %s (%s%s)\r\n", verdict, filter_policy_rule_name(v.rule_idx),
           (v.reason == DROP_REASON_RATE_LIMIT) ? ", rate-limit" : "");
  }
  else if (v.action == PKT_PASS)
  {
    printf("  => %s (default)\r\n", verdict);
  }
  else
  {
    /* malformed, bad-checksum, spoofed, tcp-scan or default */
    printf("  => %s (%s)\r\n", verdict, pkt_drop_reason_name(v.reason));
  }
}

/** Print the filter counters: totals, drops per reason, hits per rule. */
static void print_stats(void)
{
  printf("--- passed %lu | dropped:", (unsigned long)filter.passed);

  for (uint32_t r = DROP_REASON_NONE + 1u; r < DROP_REASON_COUNT; r++)
  {
    printf(" %s %lu", pkt_drop_reason_name((pkt_drop_reason_t)r), (unsigned long)filter.dropped[r]);
  }

  printf(" | hits:");
  for (uint32_t i = 0u; i < filter.rule_count; i++)
  {
    printf(" %s:%lu", filter_policy_rule_name((int32_t)i), (unsigned long)filter.rule_hits[i]);
  }

  printf(" default:%lu ---\r\n", (unsigned long)filter.default_hits);

  /* Hardware view: frames the MAC took off the wire vs. frames the filter
   * saw. MAC counts unicast only, so broadcasts (DHCP) appear only in "seen". */
  eth_rx_stats_t hw;
  eth_rx_get_stats(&hw);
  uint32_t seen = filter.passed;
  for (uint32_t r = 0u; r < DROP_REASON_COUNT; r++)
  {
    seen += filter.dropped[r];
  }
  printf("--- hw: mac rx unicast %lu | filter saw %lu | fifo-overflow %lu"
         " dma-missed %lu | rbu %lu refills %lu | free bufs %lu/%u"
         " (low: period %lu, ever %lu, empty %lu) | log-drop %lu ---\r\n",
         (unsigned long)hw.mac_rx_good, (unsigned long)seen,
         (unsigned long)hw.fifo_overflow, (unsigned long)hw.dma_missed,
         (unsigned long)hw.rbu_events, (unsigned long)hw.refills,
         (unsigned long)hw.free_bufs,
         (unsigned)ETH_RX_BUF_COUNT, (unsigned long)eth_rx_take_period_low(),
         (unsigned long)hw.free_low, (unsigned long)hw.pool_empty,
         (unsigned long)uart_log_dropped());

  /* Filter cost per frame over the last period, then start a new period. */
  if (filter_cycles.count == 0u)
  {
    printf("--- filter cycles: no frames ---\r\n");
  }
  else
  {
    uint32_t avg = (uint32_t)(filter_cycles.sum / filter_cycles.count);
    printf("--- filter cycles/frame (%lu frames): min %lu avg %lu max %lu"
           " = avg %lu ns ---\r\n",
           (unsigned long)filter_cycles.count, (unsigned long)filter_cycles.min,
           (unsigned long)avg, (unsigned long)filter_cycles.max,
           (unsigned long)perf_cycles_to_ns(avg));
    print_paths();   /* only when something new arrived, to keep the log short */
  }
  perf_reset(&filter_cycles);
}

/** Add one frame's cost to the stats of the path it took. */
static void record_path(pkt_verdict_t v, uint32_t cycles)
{
  if ((v.rule_idx >= 0) && (v.rule_idx < (int32_t)POLICY_RULE_COUNT))
  {
    perf_record((v.reason == DROP_REASON_RATE_LIMIT) ? &path_limit[v.rule_idx]
                                                     : &path_pass[v.rule_idx],
                cycles);
  }
  else if ((uint32_t)v.reason < DROP_REASON_COUNT)
  {
    perf_record(&path_reason[v.reason], cycles);
  }
}

static void print_one_path(const char *name, const char *suffix, const perf_stats_t *s)
{
  if (s->count == 0u)
  {
    return;
  }
  uint32_t avg = (uint32_t)(s->sum / s->count);
  printf("    path %-12s%-12s n=%-5lu min %5lu avg %5lu max %5lu cycles = avg %5lu ns\r\n",
         name, suffix, (unsigned long)s->count, (unsigned long)s->min,
         (unsigned long)avg, (unsigned long)s->max,
         (unsigned long)perf_cycles_to_ns(avg));
}

/** Cycles per frame for every path seen since boot. */
static void print_paths(void)
{
  printf("--- cycles by path (since boot) ---\r\n");
  for (uint32_t r = 0u; r < DROP_REASON_COUNT; r++)
  {
    print_one_path((r == DROP_REASON_NONE) ? "pass" : pkt_drop_reason_name((pkt_drop_reason_t)r),
                   "", &path_reason[r]);
  }
  for (uint32_t i = 0u; i < POLICY_RULE_COUNT; i++)
  {
    print_one_path(filter_policy_rule_name((int32_t)i), "pass", &path_pass[i]);
    print_one_path(filter_policy_rule_name((int32_t)i), "rate-limit", &path_limit[i]);
  }
}
/* USER CODE END 4 */

 /* MPU Configuration */

void MPU_Config(void)
{
  MPU_Region_InitTypeDef MPU_InitStruct = {0};

  /* Disables the MPU */
  HAL_MPU_Disable();

  /** Initializes and configures the Region and the memory to be protected
  */
  MPU_InitStruct.Enable = MPU_REGION_ENABLE;
  MPU_InitStruct.Number = MPU_REGION_NUMBER0;
  MPU_InitStruct.BaseAddress = 0x0;
  MPU_InitStruct.Size = MPU_REGION_SIZE_4GB;
  MPU_InitStruct.SubRegionDisable = 0x87;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL0;
  MPU_InitStruct.AccessPermission = MPU_REGION_NO_ACCESS;
  MPU_InitStruct.DisableExec = MPU_INSTRUCTION_ACCESS_DISABLE;
  MPU_InitStruct.IsShareable = MPU_ACCESS_SHAREABLE;
  MPU_InitStruct.IsCacheable = MPU_ACCESS_NOT_CACHEABLE;
  MPU_InitStruct.IsBufferable = MPU_ACCESS_NOT_BUFFERABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);

  /** Initializes and configures the Region and the memory to be protected
  */
  MPU_InitStruct.Number = MPU_REGION_NUMBER1;
  MPU_InitStruct.BaseAddress = 0x30000000;
  MPU_InitStruct.Size = MPU_REGION_SIZE_32KB;
  MPU_InitStruct.SubRegionDisable = 0x0;
  MPU_InitStruct.TypeExtField = MPU_TEX_LEVEL1;
  MPU_InitStruct.AccessPermission = MPU_REGION_FULL_ACCESS;
  MPU_InitStruct.IsShareable = MPU_ACCESS_NOT_SHAREABLE;

  HAL_MPU_ConfigRegion(&MPU_InitStruct);
  /* Enables the MPU */
  HAL_MPU_Enable(MPU_PRIVILEGED_DEFAULT);

}

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
