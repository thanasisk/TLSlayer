FROM golang
MAINTAINER nohohC0i
ENV SCM https://github.com/thanasisk/TLSlayer.git
ENV SCM_BRANCH master 
RUN git clone --single-branch --depth=1 -b $SCM_BRANCH $SCM /opt/tlslayer
RUN useradd -m -s /bin/sh tlslayer && chown -R tlslayer /opt/tlslayer
USER tlslayer
RUN cd /opt/tlslayer/ && go build
ENTRYPOINT ["/opt/tlslayer/tlslayer"]
