.PHONY: all run clean
CNAME = normal_web_server
CTYPE = .c
FLAGS += -g -Wall -lpthread -std=gnu11 -D__PURE_BODY__
CFLAGS += -D__TRACE__  -D__DEBUG__
UTIL = util.h httpdef.h

#all: $(CNAME) $(CPPNAME)
all: $(CNAME)

$(CNAME): $(CNAME)$(CTYPE) $(UTIL)
	gcc -o $(CNAME) $(CNAME)$(CTYPE) $(FLAGS) $(CFLAGS)

clean:
	rm -rf $(CNAME)
run:
	./$(CNAME) 11111
