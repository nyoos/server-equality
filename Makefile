# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

# Default target executed when no arguments are given to make.
default_target: all
.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/suni/Documents/Research/fhe/server-equality

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/suni/Documents/Research/fhe/server-equality

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/bin/ccmake -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache
.PHONY : edit_cache/fast

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/bin/cmake --regenerate-during-build -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache
.PHONY : rebuild_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/suni/Documents/Research/fhe/server-equality/CMakeFiles /home/suni/Documents/Research/fhe/server-equality//CMakeFiles/progress.marks
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/suni/Documents/Research/fhe/server-equality/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean
.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named server-equality

# Build rule for target.
server-equality: cmake_check_build_system
	$(MAKE) $(MAKESILENT) -f CMakeFiles/Makefile2 server-equality
.PHONY : server-equality

# fast build rule for target.
server-equality/fast:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/build
.PHONY : server-equality/fast

src/client.o: src/client.cpp.o
.PHONY : src/client.o

# target to build an object file
src/client.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/client.cpp.o
.PHONY : src/client.cpp.o

src/client.i: src/client.cpp.i
.PHONY : src/client.i

# target to preprocess a source file
src/client.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/client.cpp.i
.PHONY : src/client.cpp.i

src/client.s: src/client.cpp.s
.PHONY : src/client.s

# target to generate assembly for a file
src/client.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/client.cpp.s
.PHONY : src/client.cpp.s

src/main.o: src/main.cpp.o
.PHONY : src/main.o

# target to build an object file
src/main.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/main.cpp.o
.PHONY : src/main.cpp.o

src/main.i: src/main.cpp.i
.PHONY : src/main.i

# target to preprocess a source file
src/main.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/main.cpp.i
.PHONY : src/main.cpp.i

src/main.s: src/main.cpp.s
.PHONY : src/main.s

# target to generate assembly for a file
src/main.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/main.cpp.s
.PHONY : src/main.cpp.s

src/server.o: src/server.cpp.o
.PHONY : src/server.o

# target to build an object file
src/server.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/server.cpp.o
.PHONY : src/server.cpp.o

src/server.i: src/server.cpp.i
.PHONY : src/server.i

# target to preprocess a source file
src/server.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/server.cpp.i
.PHONY : src/server.cpp.i

src/server.s: src/server.cpp.s
.PHONY : src/server.s

# target to generate assembly for a file
src/server.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/server.cpp.s
.PHONY : src/server.cpp.s

src/test_bench.o: src/test_bench.cpp.o
.PHONY : src/test_bench.o

# target to build an object file
src/test_bench.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/test_bench.cpp.o
.PHONY : src/test_bench.cpp.o

src/test_bench.i: src/test_bench.cpp.i
.PHONY : src/test_bench.i

# target to preprocess a source file
src/test_bench.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/test_bench.cpp.i
.PHONY : src/test_bench.cpp.i

src/test_bench.s: src/test_bench.cpp.s
.PHONY : src/test_bench.s

# target to generate assembly for a file
src/test_bench.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/test_bench.cpp.s
.PHONY : src/test_bench.cpp.s

src/utils.o: src/utils.cpp.o
.PHONY : src/utils.o

# target to build an object file
src/utils.cpp.o:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/utils.cpp.o
.PHONY : src/utils.cpp.o

src/utils.i: src/utils.cpp.i
.PHONY : src/utils.i

# target to preprocess a source file
src/utils.cpp.i:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/utils.cpp.i
.PHONY : src/utils.cpp.i

src/utils.s: src/utils.cpp.s
.PHONY : src/utils.s

# target to generate assembly for a file
src/utils.cpp.s:
	$(MAKE) $(MAKESILENT) -f CMakeFiles/server-equality.dir/build.make CMakeFiles/server-equality.dir/src/utils.cpp.s
.PHONY : src/utils.cpp.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... edit_cache"
	@echo "... rebuild_cache"
	@echo "... server-equality"
	@echo "... src/client.o"
	@echo "... src/client.i"
	@echo "... src/client.s"
	@echo "... src/main.o"
	@echo "... src/main.i"
	@echo "... src/main.s"
	@echo "... src/server.o"
	@echo "... src/server.i"
	@echo "... src/server.s"
	@echo "... src/test_bench.o"
	@echo "... src/test_bench.i"
	@echo "... src/test_bench.s"
	@echo "... src/utils.o"
	@echo "... src/utils.i"
	@echo "... src/utils.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -S$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

