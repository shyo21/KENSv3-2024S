[[[[[ README for KENSv3 Programming Assignment #2 ]]]]]

<<< 1.TCPAssignment.hpp >>>

1-a. enum class socketState: 소켓의 상태를 나타내는 열거형 타입

1-b. socket: 소켓의 정보를 저장하는 구조체
    std::queue<Packet> listeningQueue;
        LISTENING중인 소켓이 하나의 패킷을 처리하는 동안 들어온 다른 패킷 요청들을 저장하는 큐. backlog의 사이즈를 가진다.
    std::queue<std::tuple<struct sockaddr_in *, struct sockaddr_in *>> acceptQueue;
        blocked 상태가 아닌 accpet 함수에게 넘겨줄 요청을 저장하는 큐
        
1-c. socketSet: 만들어진 모든 소켓 구조체를 저장하는 set

1-d. blockedProcessHandler: blocked 상태인 프로세스의 정보를 저장하는 set

1-e. 패킷에서 필요한 정보들을 불러오는 함수들(host-order로)
    uint32_t getSrcIP(Packet *);
    uint32_t getDestIP(Packet *);
    uint16_t getSrcPort(Packet *);
    uint16_t getDestPort(Packet *);
    uint8_t getFlag(Packet *);

1-f. 패킷에 필요한 정보를 write하는 함수
    void setPacketSrcDest(Packet *, uint32_t, uint16_t, uint32_t, uint16_t);

1-g. ip-port 페어를 이용해서 소켓을 탐색하는 함수
    struct Socket *getSocket(std::pair<uint32_t, in_port_t>, std::pair<uint32_t, in_port_t>);

1-h. 패킷과 소켓의 상태에 따라 해당 패킷 처리.
    void handleSYNSent(Packet *, struct Socket *);
    void handleListening(Packet *, struct Socket *);
    void handleSYNRcvd(Packet *, struct Socket *);
    void handleEstab(Packet *, struct Socket *);
    
1-i. 소켓 구조체를 안전하게 삭제하는 함수
    void deleteSocket(struct Socket *);

1-j. 시스템콜 처리 함수들
    void syscall_socket(UUID, int, int, int, int);
    void syscall_close(UUID, int, int);
    void syscall_bind(UUID, int, int, const struct sockaddr *, socklen_t);
    void syscall_getsockname(UUID, int, int, struct sockaddr *, socklen_t *);
    void syscall_listen(UUID, int, int, int);
    void syscall_connect(UUID, int, int, const struct sockaddr *, socklen_t);
    void syscall_accept(UUID, int, int, struct sockaddr *, socklen_t *);
    void syscall_getpeername(UUID, int, int, struct sockaddr *, socklen_t *);


<<< 2. TCPAssignment.cpp >>>

2-a. packetArrived
    패킷이 도착하면 패킷에 적힌 src IP, Port, dest IP,Port에 따라 socket을 지정하여
    해당 소켓의 상태에 따라 핸들해줌. getSocket함수를 통해 얻음.
    2-a-1. getSocket(destAddrPair, srcAddrPair)
        만약 socket들 중에서 established 된 친구들이 있으면 srcaddrpair까지 이용해서
        소켓을 찾아줌. 아니라면 established 된 상태가 아닌, 즉 listening중인 소켓에게로
        연결을 보냄.

    listening 중인 소켓에 패킷들이 오면 패킷을 읽고 해당 리스닝 소켓을 synrcvd로 설정.
    그 상태에서 syn 패킷을 계속해서 받으면 일단 소켓의 리스닝큐에 저장.
    accept 실행시 accept 큐가 비었다면 일단 return; 을 통해 해당 프로세스를 block.
    정보를 기억해뒀다 나중에 해당 요청을 처리중인 소켓이 ack 패킷을 처리할때 처리. ack 패킷을 받아 연결이 활성화되었다면  
    accept에서 처리할 수 있도록 정보를 app 쪽으로 옮김.


<<< 3. 경험한 다양한 error및 이를 해결한 방법 >>>

error -> 테스트 케이스에서 port 와 addr 의 값이 다른데, endian만이 다르다는 것을 확인.
solution -> application에서 쓰이는, 우리가 쓰는 모든 구조체와 함수에서는 hostorder로 통일하고, data를 적을 때에는 network order로 바꾸어서 지정.

error -> getsockname, getpeername에서 또 address 정보가 반대로 읽힌다는 것을 확인.
solution -> 해당 함수들에서 addr 정보로 주어지는 것이 network order로 되어있다는 것을 확인. 해당 부분을 확인함.

error -> getSocket 함수에서 주어진 주소 정보로 소켓을 찾을 수 없다는 에러.
solution -> network order, hostorder 통일하니 해결.

error -> listening 중인 소켓을 리턴해야하는데, established된 소켓을 출력.
solution -> 기존 getSocket은 destIP, Port 만을 사용하여 해당 ipport 쌍을 가지는 소켓을 대충 연결. 기존에 연결된 요청이 아닌 새로운 요청의 경우에는
        리스닝중인 소켓을 리턴해줌으로써 새로운 연결을 만들어야 하는데 그것이 안 되고 있었다. 그러다보니 established된 소켓을 찾아서 핸들하게 됐고, 전부 
        handleEstab으로 흘러들어가는 오류 발생. 이미 연결이 established 된 연결의 경우에는 ipport 두 쌍, 총 네 개의 정보를 똑같이 가지는 소켓을 찾아주어야함.
        그래서 established된 소켓을 먼저 비교해주어 4개의 정보를 다 같이 가지는지 살펴주었고, 나머지는 destip,port로만
        찾아주게 된다. 현재 서버쪽에 소켓이 listening, established 두 종류밖에 없다. estab된 소켓들은 4개 정보 다 비교. 연결된 소켓이 없다면 새로운 연결을
        만들어 주기 위해 리스닝소켓으로 연결.

error -> 그냥 안 돌아감.
solution -> listeingQueue의 역할을 잘못 알고 있었다. '리스닝 중인 소켓에 들어오는 요청을 받는다' 라는 것을 app에서의 accept 한다라는 개념과 동일시해서
        ack까지 받은 다음에 소켓의 listeningqueue에 pending 연결을 저장하려고 했다. 하지만 이 때 accept에서는 returnSystemCall을 통해 소켓의 리스닝큐가 비었다는
        에러 메시지와 함께 accept를 끝내버렸고 진행이 안 되었다.
        
        discussion and QnA를 읽어보며 accept, connect를 block해야 한다는 것을 발견! blockedProcessHandler를 통해 나중에 returnsystemcall을 해줄 수 있도록
        블럭할 때 해당 정보를 기억할 수 있게 했다. 

error -> SEG FAULT 발생!
solution -> 소켓 구조체 내부에 " struct sockaddr_in *myAddr = nullptr; struct sockaddr_in *connectedAddr = nullptr; "부분이 존재함.
            이 부분에 데이터를 넣을때 malloc을 통해 적절한 크기의 메모리를 할당해주지 않아서 접근시 segfault 발생하는 것 확인.
            malloc을 통해 메모리를 할당하고, 다 사용한 후 free해서 안전하게 할당 해제하는 방식으로 해결.

error -> testaccept를 할 때 syn-ack이 정상적으로 갔는데, ACK 패킷이 돌아오지 않음
solution -> checksum 자리를 별도로 초기화하지 않고 00인 상태로 두었는데, tcp_sum함수를 이용해 적절한 값을 넣어주니 정상작동

error -> connect함수에서 SYN 패킷을 보낼 때 잘못된 포트번호를 나타냄
solution -> getRoutingTable을 이용해서 획득한 port넘버는 tcp application에서 이용하는 포트가 아니었음.
            이는 라우팅테이블 인터페이스 접근에 사용되는 포트번호이므로 tcp에서 사용할 포트번호는 별도로 할당해야 함.
            이 때 랜덤한 포트를 할당하고, 해당 포트가 이미 이용중인지 확인하는 과정도 추가함으로써 다수의 에러 해결


BIG_ERROR -> handshake 0점! (packet 처리 하기 싫어서 미루면서 3-4일 packetArrived 없이 코드 처리.)
solution-> packetArrived를 짜기 시작! 조교님들의 말씀대로 diagram 참조! case나누어서 하나하나 처리! 해결!

결론. 조교님들의 말씀을 새겨듣자.






















