import socket, time, argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ip', default='192.168.76.200')
    parser.add_argument('--port', type=int, default=8888)
    parser.add_argument('--size', type=int, default=64)
    parser.add_argument('--count', type=int, default=50000)
    parser.add_argument('--local-ip', default='192.168.76.127')
    parser.add_argument('--duration', type=int, default=10)
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.05)
    sock.bind((args.local_ip, 0))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256*1024)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256*1024)

    payload = b'X' * args.size
    sent = recv = s_cnt = r_cnt = 0
    start = time.time()
    end = start + args.duration

    while time.time() < end:
        try:
            sock.sendto(payload, (args.ip, args.port))
            s_cnt += 1; sent += args.size
        except:
            pass
        try:
            data, _ = sock.recvfrom(args.size + 100)
            if data:
                r_cnt += 1; recv += len(data)
        except socket.timeout:
            pass
        except:
            pass

    elapsed = time.time() - start
    print(f'发送: {s_cnt} 包, {sent*8/elapsed/1e6:.2f} Mbps, {s_cnt/elapsed:.0f} pps')
    print(f'接收: {r_cnt} 包, {recv*8/elapsed/1e6:.2f} Mbps, {r_cnt/elapsed:.0f} pps')
    print(f'丢包: {s_cnt - r_cnt} ({(s_cnt-r_cnt)*100/max(s_cnt,1):.2f}%)')
    sock.close()

if __name__ == '__main__':
    main()