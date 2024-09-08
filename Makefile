# Colors
_BLACK			= \033[0;30m
_RED 			= \033[0;31m
_GREEN			= \033[0;32m
_BROWN			= \033[0;33m
_BLUE			= \033[0;34m
_PURPLE			= \033[0;35m
_CYAN			= \033[0;36m
_LIGHT_GRAY		= \033[0;37m
_DARK_GRAY		= \033[1;30m
_LIGHT_RED		= \033[1;31m
_LIGHT_GREEN	= \033[1;32m
_YELLOW			= \033[1;33m
_LIGHT_BLUE		= \033[1;34m
_LIGHT_PURPLE	= \033[1;35m
_LIGHT_CYAN		= \033[1;36m
_WHITE			= \033[1;37m
_NC 			= \033[0m

# Inverted, i.e. colored backgrounds
_IGREY			= \x1b[40m
_IRED			= \x1b[41m
_IGREEN			= \x1b[42m
_IYELLOW		= \x1b[43m
_IBLUE			= \x1b[44m
_IPURPLE		= \x1b[45
_ICYAN			= \x1b[46m
_IWHITE			= \x1b[47m

# Color reset
_COLOR_RESET	= \033[0m

SRC_DIR = src
OBJ_DIR = obj
INCLUDES = -I./inc

SRC_FILES = ft_ping.c ft_ping_utils.c ft_ping_parsing.c
SRC = $(addprefix $(SRC_DIR)/, $(SRC_FILES))

OBJ = $(subst $(SRC_DIR)/, $(OBJ_DIR)/, $(patsubst %.c, %.o, $(SRC)))

# CC = clang
CFLAGS := -Wall -Wextra -Werror -O3 $(INCLUDES)
LDFLAGS = -lm

TARGET = ft_ping

$(TARGET): $(OBJ)
	@echo "$(_PURPLE)Linking $(TARGET)$(_COLOR_RESET)"
	@mkdir -p $(@D)
	@$(CC) $(OBJ) -o $(TARGET) $(LDFLAGS)

all: $(TARGET)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.c
	@echo "$(_BLUE)Compiling $(basename $(notdir $*.o)) $(_COLOR_RESET)"
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

re: fclean all

fclean: clean
	@echo "$(_RED)Deleting binaries$(_COLOR_RESET)"
	@rm -rf $(TARGET) $(TESTER_TARGET)

clean:
	@echo "$(_RED)Cleaning object files$(_COLOR_RESET)"
	@rm -rf $(OBJ_DIR)

.PHONY: clean fclean re all bonus
