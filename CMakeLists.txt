cmake_minimum_required(VERSION 3.10)
project(xdpbridge)

# macro(use_clang)
#   if (CMAKE_CROSSCOMPILING AND ${CURRENT_COMPILER} STREQUAL "HOST")
#     # Save current host flags
#     set(HOST_C_FLAGS ${CMAKE_C_FLAGS} CACHE STRING "GCC flags for the host compiler." FORCE)

#     # Change compiler
#     set(CMAKE_SYSTEM_NAME ${NATIVE_SYSTEM_NAME})
#     set(CMAKE_SYSTEM_PROCESSOR ${NATIVE_SYSTEM_PROCESSOR})
#     set(CMAKE_C_COMPILER ${NATIVE_C_COMPILER})
#     set(CMAKE_C_FLAGS ${NATIVE_C_FLAGS})
#     set(CURRENT_COMPILER "NATIVE" CACHE STRING "Which compiler we are using." FORCE)
#   endif()
# endmacro()


find_program(CLANG_COMPILER clang)
find_program(LLVM_COMPILER llc)

# macro(use_clang)
#     set(CMAKE_C_COMPILER clang)
#     # add_definitions(-include ${KERNEL_TOP}/include/linux/kconfig.h)

# endmacro()

# macro(use_gcc)
#     set(CMAKE_C_COMPILER gcc)
#     # set(CMAKE_C_FLAGS ${NATIVE_C_FLAGS})
# endmacro()

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

list(TRANSFORM KERNELINCLUDE PREPEND -I)
list(TRANSFORM KERNELDEF PREPEND -D)
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    COMMAND ${CLANG_COMPILER}
    ${KERNELINCLUDE} ${KERNELDEF}  -include /home/ilejn/linux-4.18.19//include/linux/kconfig.h
    -O2
    -Wno-unused-value -Wno-pointer-sign -Wno-compare-distinct-pointer-types -Wno-gnu-variable-sized-type-not-at-end -Wno-tautological-compare -Wno-unknown-warning-option -Wno-address-of-packed-member
    -S -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/xdpbridge_kern.c
    -o ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    )

add_custom_target(xdpbridge_kern_ll ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll)




# use_clang()

add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.o
    COMMAND ${LLVM_COMPILER}
    -march=bpf -filetype=obj -o ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.o ${CMAKE_CURRENT_BINARY_DIR}/xdpbridge_kern.ll
    DEPENDS xdpbridge_kern_ll
    )

add_custom_target(xdpbridge_kern ALL DEPENDS xdpbridge_kern.o)
add_dependencies(xdpbridge_kern
    xdpbridge_kern_ll)


# add_library(xdpbridge_kern_aux OBJECT xdpbridge_kern.c)
# add_executable(xdpbridge_kern  xdpbridge_kern.c)

# target_compile_definitions(xdpbridge_kern_aux PRIVATE
#     __KERNEL__
#     __ASM_SYSREG_H
#     __BPF_TRACING__
#     __TARGET_ARCH_$(ARCH)
#     # -march=bpf
#     # -filetype=obj
#     # -S -emit-llvm -c
#     # | llc -march=bpf $(LLC_FLAGS) -filetype=obj -o $@
#     )


# target_include_directories(xdpbridge_kern_aux PRIVATE
#     ${KERNELINCLUDE}
#     )

# target_compile_options(xdpbridge_kern_aux PRIVATE
#     -include ${KERNEL_TOP}/include/linux/kconfig.h
#     -S -emit-llvm -c
#     )

# use_clang()

add_library(xdpbridge_user_object # OBJECT
    xdpbridge_user.c
    )

add_executable(xdpbridge
    xdpbridge_main.c
)

# use_clang()

# add_dependencies(xdpbridge xdpbridge_kern.o)

target_include_directories(xdpbridge PRIVATE
    ${USERINCLUDE}
    )

target_include_directories(xdpbridge_user_object PUBLIC
    ${USERINCLUDE}
    )

target_link_libraries(xdpbridge_user_object
    PRIVATE pthread
    PUBLIC ${KERNEL_TOP}/tools/lib/bpf/bpf.o
    PUBLIC ${KERNEL_TOP}/tools/lib/bpf/btf.o
    PUBLIC ${KERNEL_TOP}/tools/lib/bpf/libbpf.o
    # ${KERNEL_TOP}/tools/lib/bpf/str_error.o
    PUBLIC ${KERNEL_TOP}/tools/lib/bpf/nlattr.o
    PRIVATE elf
    )


target_link_libraries(xdpbridge
    xdpbridge_user_object
    # pthread
    # ${KERNEL_TOP}/tools/lib/bpf/bpf.o
    # ${KERNEL_TOP}/tools/lib/bpf/btf.o
    # ${KERNEL_TOP}/tools/lib/bpf/libbpf.o
    # # ${KERNEL_TOP}/tools/lib/bpf/str_error.o
    # ${KERNEL_TOP}/tools/lib/bpf/nlattr.o
    # elf
    )

# use_gcc()

# set(CMAKE_CXX_IMPLICIT_LINK_LIBRARIES "")
# set(CMAKE_CXX_IMPLICIT_LINK_DIRECTORIES "")
# set_target_properties(yourtarget PROPERTIES LINKER_LANGUAGE C)

# add_compile_options()
