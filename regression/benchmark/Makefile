MAKEFLAGS += --no-builtin-rules # Prevent the implicit rules from compiling ".c" or ".s" files automatically.

BENCHMARKS := nginx

.PHONY: all

all: 
	@for benchmark in $(BENCHMARKS); \
		do make --no-print-directory -C $${benchmark}; \
	done