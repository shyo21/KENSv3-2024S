[[[[[ README for KENSv3 Programming Assignment #2 ]]]]]

<<< 1. progress report >>>

2024/04/24 WED

- 프로젝트 시작
- 주요 성과: syscall_read(), syscall_write(), handleEstab(), sendData() 로직 구현

- socket 구조체에 std::vector<char> sendBuffer, receiveBuffer 추가
    > 보내고자 하는 모든 데이터는 sendBuffer에, 패킷에서 읽은 모든 데이터는 receiveBuffer에 저장
    > std::vector의 특성상 시스템 메모리의 한계까지 크기 증가 가능
    > 버퍼 사이즈 부족으로 인한 block은 일단 고려하지 않음

- syscall_read()
    > receiveBuffer가 비어있다면 block
    > 데이터가 들어있으면 모든 데이터를 buf로 옮김
    > buf보다 데이터의 크기가 크다면 일단 buf의 크기만큼 옮김
    > 그럼 나머지 데이터는??
    > 읽은 데이터의 크기 리턴하고 종료

- syscall_write()
    > buf에 있는 데이터를 전부 sendBuffer로 복사
    > sendBuffer에 옮겨진 데이터를 전부 패킷으로 만들어 발송 (sendData 함수 호출)
    > 보낸 데이터의 크기인 count를 리턴하고 종료

- handleEstab()
    > 받은 패킷에 헤더를 제외한 payload가 존재하는지 확인
    > 있다면 데이터를 전부 recieveBuffer로 복사
    > TODO: read()에서 blocked process인지 확인하고 해결하는 로직 구현
    > 정상적으로 복사했다면 이 패킷에 대한 ack 패킷 발송
    > TODO: 패킷 헤더 나머지부분 작성하는거 빼먹음
    > TODO: 받은 패킷이 ack인 경우 핸들링 로직 구현

- sendData()
    > 데이터 송신이 가능한 상태인지 윈도우 확인
    > 송신이 가능하다면 보낼 데이터를 담은 패킷을 생성해서 송신
    > 데이터가 패킷 하나의 MSS보다 크다면 여러개의 패킷으로 쪼개서 송신
    > 송신 후 윈도우 상태 업데이트
    > TODO: 패킷 헤더 나머지부분 작성하는거 여기도 빼먹음

- 결과 : 패킷 헤더 작성하는거 까먹어서 작동이 안됨 ㅜㅜ


2024/04/25 THU

- 주요 성과: packetInfo 구조체 생성, readData(), writeData(), writePacket() 함수 작성
            handleEstab(), sendData() 수정

- packetInfo 구조체
    > 패킷 헤더에 담긴 정보를 전부 저장하는 구조체
    > sendData 함수에서 헤더부분 작성을 위해서 정보를 전달해야 할 필요성에 의해 생성
    > 만들고 보니 이거 쓰면 패킷 read write할 때 중복해서 사용하던 긴 코드들 삭제할 수 있을듯?

- readData()
    > 패킷과 packetInfo 구조체를 입력받아 패킷에 있는 모든 헤더 정보를 구조체에 복사
    > host order로 변환해서 저장함
    > ip 헤더와 tcp 헤더의 정보 전부 들고있음

- writeData()
    > 주어진 packetInfo 구조체에 있는 정보를 패킷에 전부 적어넣음
    > network order로 변환해서 적음

- handleEstab()
    > blocked process 처리하는 로직 추가
    > 