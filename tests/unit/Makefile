MAKEFLAGS	+=	--no-print-directory

RM			?=	rm -f
ECHO		=	`which echo`

ifneq (,$(findstring xterm,${TERM}))
GREEN       := $(shell tput -Txterm setaf 2)
RED         := $(shell tput -Txterm setaf 1)
CYAN         := $(shell tput -Txterm setaf 6)
RESET 		:= $(shell tput -Txterm sgr0)
else
GREEN       := ""
RED         := ""
RESET       := ""
endif

BUILD_DIRECTORY	=	$(realpath build/)

DIRECTORY_BUILD = build
SOURCE_DIRECTORY = $(realpath .)

all:
	@if [ -f ${DIRECTORY_BUILD}/CMakeCache.txt ] && ! grep -Fq "CMAKE_HOME_DIRECTORY:INTERNAL=${SOURCE_DIRECTORY}" ${DIRECTORY_BUILD}/CMakeCache.txt; then $(ECHO) -e "${RED}[ RM ]${RESET}" ${DIRECTORY_BUILD} "(stale CMake cache)"; $(RM) -r ${DIRECTORY_BUILD}; fi;
	@cmake -B ${DIRECTORY_BUILD} -H.
	@make -C ${DIRECTORY_BUILD}
	@CTEST_OUTPUT_ON_FAILURE=1 make -C ${DIRECTORY_BUILD} test

coverage: all
	@if ! command -v lcov >/dev/null 2>&1; then $(ECHO) "lcov is required for coverage. Install it with 'brew install lcov' on macOS or your package manager on Linux."; exit 127; fi
	@if ! command -v genhtml >/dev/null 2>&1; then $(ECHO) "genhtml is required for coverage. Install the 'lcov' package first."; exit 127; fi
	@lcov --directory . -b "${BUILD_DIRECTORY}" --capture --initial -o coverage.base
	@lcov --rc lcov_branch_coverage=1 --directory . -b "${BUILD_DIRECTORY}" --capture -o coverage.capture
	@lcov --directory . -b "${BUILD_DIRECTORY}" --add-tracefile coverage.base --add-tracefile coverage.capture -o coverage.info
	@lcov --directory . -b "${BUILD_DIRECTORY}" --remove coverage.info '*/tests/unit/tests/*' '*/build/_deps/cmocka-src/src/*' -o coverage.info
	@$(ECHO) -e "${GREEN}[ OK ]${RESET} Generated 'coverage.info'."
	@genhtml coverage.info -o coverage
	@if [ -f coverage.base ]; then $(ECHO) -e "${RED}[ RM ]${RESET}" coverage.base && $(RM) -r coverage.base ; fi;
	@if [ -f coverage.capture ]; then $(ECHO) -e "${RED}[ RM ]${RESET}" coverage.capture && $(RM) -r coverage.capture ; fi;
	@if command -v xdg-open >/dev/null 2>&1; then $(ECHO) -e "${CYAN}[ REDIRECT ]${RESET}" `realpath coverage/index.html` && xdg-open `realpath coverage/index.html`; elif command -v open >/dev/null 2>&1; then $(ECHO) -e "${CYAN}[ REDIRECT ]${RESET}" `realpath coverage/index.html` && open `realpath coverage/index.html`; else $(ECHO) -e "${CYAN}[ COVERAGE ]${RESET}" `realpath coverage/index.html`; fi

clean:
	@if [ -d ${DIRECTORY_BUILD} ]; then $(ECHO) -e "${RED}[ RM ]${RESET}" ${DIRECTORY_BUILD} && $(RM) -r ${DIRECTORY_BUILD} ; fi;
	@if [ -d coverage ]; then $(ECHO) -e "${RED}[ RM ]${RESET}" coverage && $(RM) -r coverage ; fi;
	@if [ -f coverage.info ]; then $(ECHO) -e "${RED}[ RM ]${RESET}" coverage.info && $(RM) -r coverage.info ; fi;

.PHONY: all coverage clean
