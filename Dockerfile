FROM ubuntu:24.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Version configurations
ENV LLVM_VERSION=13

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    git \
    libgoogle-perftools-dev \
    python3 \
    python3-pip \
    parallel \
    gcc-multilib \
    g++-multilib \
    graphviz \
    libnuma-dev \
    cmake \
    file \
    libcap-dev \
    libncurses5-dev \
    libsqlite3-dev \
    libtcmalloc-minimal4 \
    unzip \
    doxygen \
    libelf-dev \
    time \
    zlib1g-dev \
    pkgconf \
    wget \
    libbpf-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and install LLVM 13
RUN wget https://github.com/llvm/llvm-project/releases/download/llvmorg-13.0.0/clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz && \
    tar -xf clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04.tar.xz && \
    LLVM_DIR=clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04 && \
    if [ -d "$LLVM_DIR/bin" ]; then cp -r $LLVM_DIR/bin/* /usr/local/bin/; fi && \
    if [ -d "$LLVM_DIR/include" ]; then cp -r $LLVM_DIR/include/* /usr/local/include/; fi && \
    if [ -d "$LLVM_DIR/lib" ]; then cp -r $LLVM_DIR/lib/* /usr/local/lib/; fi && \
    if [ -d "$LLVM_DIR/libexec" ]; then mkdir -p /usr/local/libexec && cp -r $LLVM_DIR/libexec/* /usr/local/libexec/; fi && \
    if [ -d "$LLVM_DIR/share" ]; then cp -r $LLVM_DIR/share/* /usr/local/share/; fi && \
    rm -rf clang+llvm-13.0.0-x86_64-linux-gnu-ubuntu-20.04* && \
    ldconfig

# Install Python dependencies
RUN pip3 install --no-cache-dir --break-system-packages \
    jinja2 \
    pyyaml \
    pyelftools

# Create directory structure
WORKDIR /opt/krakenguard
RUN mkdir -p bin lib include templates daemon \
    /data/requests /data/logs /sys/fs/bpf \
    dependencies

# Set up LLVM paths - using host system's LLVM tools from /usr/local/bin
ENV PATH="/opt/krakenguard/bin:/usr/local/bin:${PATH}"
ENV LLVM_CONFIG=/usr/local/bin/llvm-config

# ============================================
# Copy and Build Z3
# ============================================
COPY dependencies/z3 /opt/krakenguard/dependencies/z3
WORKDIR /opt/krakenguard/dependencies/z3
RUN python3 scripts/mk_make.py -p /opt/krakenguard/dependencies/z3/build && \
    cd build && \
    make -j$(nproc) && \
    make install

# ============================================
# Copy and Build klee-uclibc
# ============================================
COPY dependencies/klee-uclibc /opt/krakenguard/dependencies/klee-uclibc
WORKDIR /opt/krakenguard/dependencies/klee-uclibc
RUN ./configure \
        --make-llvm-lib \
        --with-llvm-config=/usr/local/bin/llvm-config \
        --with-cc=/usr/local/bin/clang && \
    make -j$(nproc)

# ============================================
# Copy and Build KLEE
# ============================================
COPY klee /opt/krakenguard/klee
WORKDIR /opt/krakenguard/klee
RUN mkdir -p build && cd build && \
    CMAKE_PREFIX_PATH="/opt/krakenguard/dependencies/z3/build" \
    CMAKE_INCLUDE_PATH="/opt/krakenguard/dependencies/z3/build/include/" \
    cmake \
        -DENABLE_UNIT_TESTS=OFF \
        -DENABLE_SYSTEM_TESTS=OFF \
        -DBUILD_SHARED_LIBS=OFF \
        -DLLVM_CONFIG_BINARY=/usr/local/bin/llvm-config \
        -DLLVMCC=/usr/local/bin/clang \
        -DLLVMCXX=/usr/local/bin/clang++ \
        -DENABLE_SOLVER_Z3=ON \
        -DENABLE_KLEE_UCLIBC=ON \
        -DKLEE_UCLIBC_PATH=/opt/krakenguard/dependencies/klee-uclibc \
        -DENABLE_POSIX_RUNTIME=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DENABLE_KLEE_ASSERTS=ON \
        .. && \
    make -j$(nproc)

# Copy KLEE binary to bin directory
RUN cp /opt/krakenguard/klee/build/bin/klee /opt/krakenguard/bin/

# ============================================
# Copy and Build BPF Lifter
# ============================================
COPY bpf_lifter /opt/krakenguard/bpf_lifter
WORKDIR /opt/krakenguard/bpf_lifter
RUN mkdir -p build && cd build && \
    LLVM_DIR=/usr/local/lib/cmake/llvm \
    cmake .. -DKRAKENGUARD_HOME=/opt/krakenguard && \
    make -j$(nproc)

# Copy bpflifter binary to bin directory
RUN cp /opt/krakenguard/bpf_lifter/build/bpflifter_cli /opt/krakenguard/bin/

# ============================================
# Copy and Build LLVM Passes
# ============================================
COPY lifting_tools /opt/krakenguard/lifting_tools

# Build func_pass
WORKDIR /opt/krakenguard/lifting_tools/llvm_func_pass
RUN mkdir -p build && cd build && \
    LLVM_DIR=/usr/local/lib/cmake/llvm \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make

# Build ext_sym_pass
WORKDIR /opt/krakenguard/lifting_tools/llvm_ext_sym_pass
RUN mkdir -p build && cd build && \
    LLVM_DIR=/usr/local/lib/cmake/llvm \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make

# Copy LLVM passes to lib directory
RUN cp /opt/krakenguard/lifting_tools/llvm_func_pass/build/libfunc_pass.so /opt/krakenguard/lib/ && \
    cp /opt/krakenguard/lifting_tools/llvm_ext_sym_pass/build/libext_sym_pass.so /opt/krakenguard/lib/

# ============================================
# Copy and Build eBPF-SE libbpf-stubbed
# ============================================
COPY ebpf-se /opt/krakenguard/ebpf-se
WORKDIR /opt/krakenguard/ebpf-se/libbpf-stubbed/src
RUN bash build.sh


# ============================================
# Copy remaining components
# ============================================
# Copy verification tools
COPY verification_tools /opt/krakenguard/verification_tools

WORKDIR /opt/krakenguard

# Copy daemon code
COPY daemon /opt/krakenguard/daemon

# Create headers directory and copy libbpf-stubbed headers
RUN mkdir -p /opt/krakenguard/include/headers && \
    cp -r /opt/krakenguard/ebpf-se/libbpf-stubbed /opt/krakenguard/include/libbpf-stubbed

# Copy Z3 libraries to lib directory
RUN cp /opt/krakenguard/dependencies/z3/build/lib/libz3.so* /opt/krakenguard/lib/ || true

# Copy KLEE runtime libraries
RUN mkdir -p /opt/krakenguard/lib/klee-runtime && \
    cp -r /opt/krakenguard/klee/build/runtime/lib/* /opt/krakenguard/lib/klee-runtime/ || true

# ============================================
# Final environment setup
# ============================================
ENV KRAKENGUARD_HOME=/opt/krakenguard
ENV PATH="${KRAKENGUARD_HOME}/bin:/usr/local/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/krakenguard/lib:/opt/krakenguard/dependencies/z3/build/lib:/usr/local/lib:/usr/lib/x86_64-linux-gnu"
ENV KLEE_INCLUDE=/opt/krakenguard/klee/include
ENV PYTHONPATH="/opt/krakenguard"
ENV FUNC_PASS_LIB=/opt/krakenguard/lifting_tools/llvm_func_pass/build/libfunc_pass.so
ENV EXT_SYM_PASS_LIB=/opt/krakenguard/lifting_tools/llvm_ext_sym_pass/build/libext_sym_pass.so

WORKDIR /opt/krakenguard

# Run daemon as a module to support relative imports
ENTRYPOINT ["python3", "-m", "daemon.krakenguard"]
