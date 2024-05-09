[[[[[ README for KENSv3 Programming Assignment #3 ]]]]]

<<< 1.TCPAssignment.hpp >>>

1-a. unackedInfo 구조체
    답변을 반드시 반아야 하는 패킷들을 발송한 뒤 그에 관한 정보들을 보관하는 구조체이다.

1-2. enum class SocketState
    소켓의 상태를 정의한다. close를 위해 상태를 추가했다.

1-3. socket 구조체
    함수 전체에서 유지되어야 하는 소켓의 여러 세부 정보를 보관하는 구조체이다.

1-4. enum class blockedState
    특정 프로세스를 블록할 때 이 프로세스가 어떤 시스템 콜에서 블록되었는지 표지하기 위한 상태이다.

1-5. blockedProcess 구조체
    블록해야 하는 프로세스를 블록한 뒤 기억해야 하는 정보들을 보관하는 구조체이다.

1-6. packetInfo 구조체
    패킷 헤더에 존재하는 정보들을 구역별로 나누어 보관하는 구조체이다.

PA2와의 주요 변경점은 unackedInfo와 blockedProcess 구조체를 추가한 점이다.
데이터 전송을 구현하는 과정에서 기존의 unackedPackets 벡터와 blockedProcess 벡터에 저장해야 할 정보의 가짓수가 많아지게 되었다.
이를 모두 벡터 안의 튜플 형식으로 저장하다 보니 접근이 비직관적이며 코드가 길고 난잡해져 따로 구조체를 만들어 관리하게 변경하였다.


<<< 2.TCPAssignment.cpp >>>

2-a. readPacket
    패킷헤터의 모든 정보를 읽어와 packetInfo 구조체에 호스트 바이트 오더로 복사하는 함수이다.

2-b. writePacket
    packetInfo 구조체에 있는 모든 정보를 패킷 헤더의 올바른 구역에 적어넣는 함수이다.

2-c. writeCheckSum
    패킷의 체크섬을 게산해 적어넣는 함수이다.

2-d. isCheckSum
    패킷의 체크섬이 올바른 값인지 확인하는 함수이다.

이상 4개의 함수는 PA2에서 쪼개져서 존재하던 패킷을 읽고 쓰는 함수들을 깔끔하게 통합한 버전이다.

2-e. getSocket

2-f. packetArrived
    패킷이 도착하면 체크섬을 확인하는 로직을 추가했다.
    또한 늘어난 소켓 스테이트에 대응하는 패턴 매칭을 추가했다.

2-g. 이하 모든 함수들은 패킷이 도착했을 때 각각의 state별로 어떤 일을 해야 하는지 정의한 함수들이다.
    기본적으로 PA2 document에 있는 state diagram을 기반으로 작성하였다.
    이에 추가로 랜덤 시드로 test case를 돌리는 과정에서 발견한 수많은 예외사항에 대한 처리도 최대한 추가했다.

    특히 unreliable 환경에서는 각 state마다 예상되는 플래그의 패킷만 도달하는 것이 아니라 더 까다로웠다.
    state에 알맞지 않은 패킷이 도달할 때 현재 진행중인 timer를 어떻게 재설정할지, 어떤 패킷을 재전송할지,
    처리 후 소켓의 상태는 어떻게 바꾸어야 할 지 파악하는데 오랜 시간이 걸렸다.