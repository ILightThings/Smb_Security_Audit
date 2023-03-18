FROM kalilinux/kali-rolling
WORKDIR /smb_audit
RUN apt update -y
RUN apt install python3 python3-impacket -y
COPY . .
CMD ["python3","main.py","192.168.1.24"]

