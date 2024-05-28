[[[[[ README for KENSv3 Programming Assignment #4 ]]]]]

<<< 1.PWOSPFAssignment.hpp/.cpp >>>

1-a. router_t 구조체
	내 라우터의 정보를 저장하는 구조체
	내가 발송한 seqnum, 내 areaID, routerID, lsuint 저장
	내가 가진 모든 인터페이스 정보 저장하는 set 포함

1-b. interface_t 구조체
	라우터에 저장된 interface 정보 저장

1-c. topology_map
	라우터 ID -> 이 라우터와 네이버인 라우터의 ID -> 링크 cost
	라우터별로 각 라우터와 직접 네이버관계를 형성한 모든 라우터와 거기까지의 코스트를 기억한다.

1-d. interface_map
	라우터 1번  id -> 연결된 인터페이스 0 ip -> 마스크
			-> 연결된 인터페이스 1 ip -> 마스크
			…

	라우터 2번 id -> …

	라우터별로 거느린 모든 인터페이스의 ip와 마스크를 기억한다.

1-e. seq_map
	라우터 ID -> 직전에 받은 시퀀스 넘버
	라우터별로 처리한 시퀀스 넘버 기록, flooding으로 넘어오는 패킷 처리하기 위함.

1-f. cost_map
	라우터 ID -> 해당 라우터까지 최적 경로의 cost
	다익스트라 알고리즘으로 topology_map에 기록된 정보를 바탕으로 현재 나의 라우터(my_router)에서 임의의 라우터까지의 코스트를 기록.

1-g. Implemented functions
	1) 패킷 종류별로 읽고 해당 정보를 포함한 구조체 리턴
		pwospf_header_t *readOSPFHeader(Packet *);
		pwospf_hello_t *readHello(Packet *);
		pwospf_lsu_t *readLSU(Packet *);

	2) 패킷을 보낼때 양식에 맞게 write
  		void writeOSPFHeader(Packet *, pwospf_header_t *);
  		void writeHello(Packet *, pwospf_hello_t *);
  		void writeLSU(Packet *, pwospf_lsu_t *);

	3) hello packet, LSU packet 따로 처리
 		void handleHello(Packet *);
 		void handleLSU(Packet *);



<<< 2.대략적인 작동 로직 >>>

2-a. initialize()
	내 라우터 구조체와 인터페이스 구조체에 나에 대한 모든 정보를 저장.
	인터페이스마다 알맞은 Hello 패킷을 만들어 발송.

2-b. handleHello()
	hello packet을 받으면 packet 을 보낸 라우터를 neighbor로 기록.
	이 정보를 LSU packet에 기록해 neighbor 라우터들에 전달.
	topology_map에 내 라우터 -> 이웃 라우터의 링크가 cost의 비용으로 존재함을 기록
	dijkstra 알고리즘 실행해 cost_map 구축

2-c. handleLSU()
	LSU 패킷을 받으면 처리했던 패킷인지 seq-map을 통해 비교후 처음 받은 패킷이라면 처리.
	topology_map에 해당 라우터가 어떤 라우터와 이웃해있고 cost는 얼마인지 기록.
	interface_map에 해당 라우터에 어떤 인터페이스들이 있는지 기록.
	ttl이 0이 아니라면 온 방향을 제외한 모든 neighbor들에 패킷 flooding.
	ttl 1 감소
	dijkstra 알고리즘 실행해 cost_map 구축

2-d. pwospfquery()
	목적지 ip가 속한 서브넷 탐색 - longest prefix match
	해당 서브넷에 연결된 라우터들 모두 식별
	식별된 라우터 중 가장 cost가 낮은 라우터 선택


조교님들 한 학기동안 고생많으셨습니다.
저희도 고생 좀(많이) 한 것 같아요.
랜덤팀메 찾아달라고 이메일도 드리고 그랬는데, KLMS에 공간 만들어주신 덕분에 좋은 팀메 만났습니다. ㅎㅎ
열심히 했으니 점수 잘 주실 거라 믿습니다… - 기민수 드림


군대때문에 2년간 휴학하면서 아예 공부를 놔버려서 걱정을 많이 했습니다.
하지만 조교님들께서 바보같은 질문들에도 친절하고 빠르게 답해주셔서 도망가지않고 끝까지 완주할수 있었습니당.
교수님과 조교님들 모두 정말 감사합니다.
기말고사 쉽게내주세요 ㅠㅠㅠㅠㅠ - 김수효 드림


