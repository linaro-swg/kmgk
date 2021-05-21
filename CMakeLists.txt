cmake_minimum_required (VERSION 3.2)
project (kmgk C)

# https://cmake.org/Wiki/CMake_Useful_Variables
set (CMAKE_TOOLCHAIN_FILE CMakeToolchain.txt)

include(GNUInstallDirs)

add_compile_options (-Wall)
#add_compile_options (
#	-Wall -Wbad-function-cast -Wcast-align
#	-Werror-implicit-function-declaration -Wextra
#	-Wfloat-equal -Wformat-nonliteral -Wformat-security
#	-Wformat=2 -Winit-self -Wmissing-declarations
#	-Wmissing-format-attribute -Wmissing-include-dirs
#	-Wmissing-noreturn -Wmissing-prototypes -Wnested-externs
#	-Wpointer-arith -Wshadow -Wstrict-prototypes
#	-Wswitch-default -Wunsafe-loop-optimizations
#	-Wwrite-strings -Werror -fPIC
#)

find_program(CCACHE_FOUND ccache)
if(CCACHE_FOUND)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
	set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif(CCACHE_FOUND)

# No subdir is actually added since we don't have any subdir
# CMakeLists.txt to build normal world targets
# since those need to be built in AOPS userspace using clang.
# This file exists only to trigger
# KMGK_EXT_POST_BUILD_HOOKS += KMGK_EXT_BUILD_TAS
# in build/br-ext/package/kmgk_ext/kmgk_ext.mk ..
file(GLOB dirs *)
foreach(dir ${dirs})
	if(EXISTS ${dir}/CMakeLists.txt)
		add_subdirectory(${dir})
	endif()
endforeach()

# .. but we still need a normal world target here
# so that cmake/buildroot can generate
# out-br/build/kmgk_ext-1.0/Makefile with an 'install/fast' target
# to install it to the root FS so that
# KMGK_EXT_POST_INSTALL_TARGET_HOOKS += KMGK_EXT_INSTALL_TAS
# in build/br-ext/package/kmgk_ext/kmgk_ext.mk can then kick in
# to copy the TAs to the root FS.
# Without a normal world target here
# out-br/build/kmgk_ext-1.0/Makefile isn't generated and
# we get an "'install/fast' target not found" build error.
# Below line simulates a dummy normal world target for this purpose.
# No actual normal world target is built or installed.
install(FILES /dev/null DESTINATION /dev/null)
