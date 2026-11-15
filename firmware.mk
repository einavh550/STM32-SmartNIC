# Standalone firmware build for CI (GitHub Actions) and the command line.
#
# STM32CubeIDE keeps its own generated makefile in Debug/ (not in git, and full
# of Windows paths), so CI cannot use it. This file builds the same .elf with
# the same compiler flags as the CubeIDE Debug configuration.
#
#   make -f firmware.mk          # build build/fw/STM32-SmartNIC.elf
#   make -f firmware.mk clean
#
# Needs arm-none-eabi-gcc in PATH.

TARGET   := STM32-SmartNIC
BUILD    := build/fw
LDSCRIPT := STM32H723ZGTX_FLASH.ld

CC   := arm-none-eabi-gcc
SIZE := arm-none-eabi-size

# Every source CubeIDE compiles: our code, the HAL, the Nucleo BSP, startup.
C_SRCS := $(wildcard Core/Src/*.c) \
          $(wildcard Drivers/STM32H7xx_HAL_Driver/Src/*.c) \
          $(wildcard Drivers/BSP/STM32H7xx_Nucleo/*.c)
S_SRCS := Core/Startup/startup_stm32h723zgtx.s

CPU := -mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard

DEFS := -DDEBUG -DUSE_PWR_LDO_SUPPLY -DUSE_HAL_DRIVER -DSTM32H723xx

INCS := -ICore/Inc \
        -IDrivers/STM32H7xx_HAL_Driver/Inc \
        -IDrivers/STM32H7xx_HAL_Driver/Inc/Legacy \
        -IDrivers/BSP/STM32H7xx_Nucleo \
        -IDrivers/CMSIS/Device/ST/STM32H7xx/Include \
        -IDrivers/CMSIS/Include

# Same as CubeIDE Debug, plus -Werror: in CI any warning fails the build.
CFLAGS := $(CPU) -std=gnu11 -g3 -O0 $(DEFS) $(INCS) \
          -ffunction-sections -fdata-sections -Wall -Werror \
          --specs=nano.specs -MMD -MP

ASFLAGS := $(CPU) -g3 -DDEBUG -x assembler-with-cpp --specs=nano.specs

LDFLAGS := $(CPU) -T$(LDSCRIPT) --specs=nosys.specs --specs=nano.specs \
           -Wl,-Map=$(BUILD)/$(TARGET).map -Wl,--gc-sections -static \
           -Wl,--start-group -lc -lm -Wl,--end-group

OBJS := $(addprefix $(BUILD)/,$(C_SRCS:.c=.o) $(S_SRCS:.s=.o))

.PHONY: all clean
all: $(BUILD)/$(TARGET).elf

$(BUILD)/$(TARGET).elf: $(OBJS) $(LDSCRIPT)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)
	$(SIZE) $@

$(BUILD)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/%.o: %.s
	@mkdir -p $(dir $@)
	$(CC) $(ASFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD)

-include $(OBJS:.o=.d)
