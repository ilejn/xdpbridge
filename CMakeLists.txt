cmake_minimum_required(VERSION 3.9)
project(xdpbridge)

find_program(CLANG_COMPILER clang)
find_program(LLVM_COMPILER llc)

set(KERNEL_TOP CACHE FILEPATH "path to the top of linux kernel sources")

if(NOT KERNEL_TOP)
    message (FATAL_ERROR "KERNEL_TOP variable does not exist")
else()
    message (STATUS "KERNEL_TOP is ${KERNEL_TOP}")
endif(NOT KERNEL_TOP)

set(KERNELINCLUDE
    ${KERNEL_TOP}/arch/x86/include
    ${KERNEL_TOP}/arch/x86/include/generated/uapi
    ${KERNEL_TOP}/arch/x86/include/generated
    ${KERNEL_TOP}/include
    ${KERNEL_TOP}/arch/x86/include/uapi
    ${KERNEL_TOP}/include/uapi
    ${KERNEL_TOP}/include/generated/uapi
    # ${KERNEL_TOP}/include/linux/kconfig.h
    ${KERNEL_TOP}/tools/lib
    ${CMAKE_CURRENT_SOURCE_DIR}
    )

set(USERINCLUDE
    ${KERNEL_TOP}/usr/include
    # ${KERNEL_TOP}/usr/include/linux
    ${KERNEL_TOP}/tools/include
    ${KERNEL_TOP}/tools/lib
    )
set(KERNELDEF
    __KERNEL__
    __ASM_SYSREG_H
    __BPF_TRACING__
    __TARGET_ARCH_$(ARCH)
    )

FUNCTION(LIST_TRANSFORM_PREPEND var prefix)
   SET(listVar "")
   FOREACH(f ${ARGN})
      LIST(APPEND listVar "${prefix}${f}")
   ENDFOREACH(f)
   SET(${var} "${listVar}" PARENT_SCOPE)
ENDFUNCTION(LIST_TRANSFORM_PREPEND)

# list(TRANSFORM KERNELINCLUDE PREPEND -I)
LIST_TRANSFORM_PREPEND(KERNELINCLUDE -I ${KERNELINCLUDE})
# list(TRANSFORM KERNELDEF PREPEND -D)
LIST_TRANSFORM_PREPEND(KERNELDEF -D ${KERNELDEF})

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    COMMAND ${CLANG_COMPILER}
    ${KERNELINCLUDE} ${KERNELDEF}  -include ${KERNEL_TOP}/include/linux/kconfig.h -include asm_goto_workaround.h
    -O2
    -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-compare -Wno-unknown-warning-option -Wno-address-of-packed-member
    -S -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/xdpbridge_kern.c
    -o ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/xdpbridge_kern.c
    )

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.o
    COMMAND ${LLVM_COMPILER}
    -march=bpf -filetype=obj -o ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.o ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    COMMENT "custom_command for xdpbridge_kern.o"
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    )

add_custom_target(xdpbridge_kern ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.o
    COMMENT "custom_target xdpbridge_kern"
    )

add_library(xdpbridge_user_object SHARED
    xdpbridge_user.c
    bpf_load.c
    )

if(NO_ABORT_ON_LASSERT_MODE)
    target_compile_definitions(xdpbridge_user_object PRIVATE NO_ABORT_WITH_LASSERT)
endif(NO_ABORT_ON_LASSERT_MODE)

add_executable(xdpbridge
    xdpbridge_main.c
    )

target_include_directories(xdpbridge PRIVATE
    ${USERINCLUDE}
    )

target_include_directories(xdpbridge_user_object PUBLIC
    ${USERINCLUDE}
    )

target_link_libraries(xdpbridge_user_object
    PUBLIC pthread
    #PUBLIC ${KERNEL_TOP}/tools/lib/bpf/bpf.o
    #PUBLIC ${KERNEL_TOP}/tools/lib/bpf/btf.o
    ## ${KERNEL_TOP}/tools/lib/bpf/str_error.o
    #PUBLIC ${KERNEL_TOP}/tools/lib/bpf/nlattr.o
    #PUBLIC ${KERNEL_TOP}/tools/lib/bpf/libbpf.o
    PUBLIC ${KERNEL_TOP}/tools/lib/bpf/libbpf.a
    PUBLIC elf
    )


target_link_libraries(xdpbridge
    xdpbridge_user_object
    )
