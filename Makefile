CC = cc
SRC = $(wildcard src/*.c)
HR = $(wildcard include/*.h)
OBJ = $(patsubst src/%.c, build/%.o, $(SRC))
CFLAGS =
NAME = ft_nmap
DEBUG ?= 0 
INTERFACE ?= enp0s3
SERVS_DATABASE ?= database/services
TERM_WIDTH := $(shell tput cols)

CFLAGS += -D DEBUG=$(DEBUG)
CFLAGS += -D INTERFACE=\"$(INTERFACE)\"
CFLGAS += -D SERVS_DATABASE=\"$(SERVS_DATABASE)\"
CFLAGS += -D TERM_WIDTH=$(TERM_WIDTH)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ)

build/%.o: src/%.c $(HR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -Iinclude -c $< -o $@

clean:
	rm -rf build

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY: clean
