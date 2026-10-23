FROM scratch

# Build this first with ./build.sh --static.
COPY --chmod=0755 out/bash-static /bin/bash-os
SHELL ["/bin/bash-os", "-c"]

RUN mkdir -p /tmp /root /etc && \
    chmod 1777 /tmp && \
    ln -s bash-os /bin/bash && \
    ln -s bash-os /bin/sh && \
    printf 'root:x:0:0:root:/root:/bin/bash-os\n' > /etc/passwd && \
    printf 'root:x:0:\n' > /etc/group

ENV PATH=/bin HOME=/root LANG=C LC_ALL=C
WORKDIR /work
ENTRYPOINT ["/bin/bash-os"]
