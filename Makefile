NAME		=	ft_ping
CC			=	gcc -g
RED			=	\033[0;31m
CYAN		=	\033[0;36m
COLOR_OFF	=	\033[0m\0
YELLOW		=	\033[0;33m
FLAGS		=	-Wextra -Werror
SRCS_DIR	=	./srcs
OBJS_DIR	=	objs
SRCS		= main.c utils.c

OBJS		=	$(SRCS:%.c=$(OBJS_DIR)/%.o)

all:	$(NAME)

$(NAME):	$(OBJS)
			@$(CC) $(FLAGS) -o  $@ $^ $(LIB) $(LDFLAGS)


$(OBJS): $(OBJS_DIR)/%.o: $(SRCS_DIR)/%.c
			@mkdir -p $(@D)
			@echo "$(RED)[**] Compiling $< [**] $(COLOR_OFF)"
			@$(CC) $(FLAGS) $(INC) $(HEADER) -o $@ -c $<

clean:
			@rm -rf $(OBJS_DIR)
			@echo "$(YELLOW)Objects Files has been removed.$(COLOR_OFF)"

fclean:		clean
			@rm -rf $(NAME)
			@echo "$(YELLOW)Binary file has been removed.$(COLOR_OFF)"

re:			fclean all

.PHONY:		all clean fclean re
