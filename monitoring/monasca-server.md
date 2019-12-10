Monasca Server 설치 가이드
==========================

1. [개요](#1.)
    * [문서 목적](#1.1.)
    * [범위](#1.2.)
    * [참고자료](#1.3.)
2. [Pre-Requisite(전제조건)](#2.)
3. [MariaDB 설치 및 데이터베이스 설정](#3.)
4. [Apache Zookeeper 설치](#4.)
5. [Apache Kafka 설치](#5.)
6. [Apache Storm 설치](#6.)
7. [InfluxDB 설치](#7.)
8. [Monasca Persister 설치](#8.)
9. [Monasca Common 설치](#9.)
10. [Monasca Thresh 설치](#10.)
11. [Monasca Notification 설치](#11.)

12. [Monasca API 설치](#12.)
13. [Elasticsearch 관련 프로그램 설치](#13.)
    * [Elasticserarch 서버 설치](#13.1.)
    * [logstash 설치](#13.2.)
14. [Reference : Cross-Project(Tenant) 사용자 추가 및 권한 부여](#14.)
    
# 1.  개요  <div id='1.'/>
# 1.1.  문서 목적  <div id='1.1.'/>
본 문서(설치가이드)는, IaaS(Infrastructure as a Service) 중 하나인 Openstack 기반의 Cloud 서비스 상태 및 자원 정보, 그리고 VM Instance의 시스템 정보를 수집 및 관리하고, 사전에 정의한 Alarm 규칙에 따라 실시간으로 모니터링하여 관리자에게 관련 정보를 제공하기 위한 서버를 설치하는데 그 목적이 있다.
# 1.2.  범위  <div id='1.2.'/>
본 문서의 범위는 Openstack 모니터링을 위한 오픈소스인 Monasca 제품군의 설치 및 관련
S/W(Kafka, Zookeeper, InfluxDB, MariaDB) 설치하기 위한 내용으로 한정되어 있다.
# 1.3.  참고자료  <div id='1.3.'/>
https://wiki.openstack.org/wiki/Monasca
http://kafka.apache.org/quickstart (version: 2.9.2)
https://zookeeper.apache.org/doc/r3.3.4/zookeeperStarted.html
https://docs.influxdata.com/influxdb/v1.5/introduction/installation/
https://mariadb.org/mariadb-10-2-7-now-available/
https://github.com/monasca/monasca-docker

# 2.  Pre-Requisite(전제조건)  <div id='2.'/>
- Monasca Server를 설치하기 위해서는 Bare Metal 서버 또는 Openstack 에서 생성한 Instance(Ubuntu 기준, Flavor - x1.large 이상)가 준비되어 있어야 한다.
- Openstack Cross-tenant 설정이 되어 있어야 한다.
<br>Reference : Cross-Project(Tenant) 사용자 추가 및 권한 부여 (openstack 기준)
- Monasca Server 설치에 필요한 프로그램 리스트 및 버전은 아래 사항을 참조한다.
- Monasca Server 를 설치하기에 필요한 프로그램을 사전에 설치한다.
- 설치 환경은 Ubuntu 18.04 , OpenStack Stein 기준으로 작성하였다.

※ 설치 프로그램 리스트 및 버전 참조 (순서)<br>
- INFLUXDB_VERSION=1.3.2-alpine
- INFLUXDB_INIT_VERSION=latest
- MYSQL_VERSION=5.5
- MYSQL_INIT_VERSION=1.5.1
- MEMCACHED_VERSION=1.5.0-alpine
- CADVISOR_VERSION=v0.26.1
- ZOOKEEPER_VERSION=3.4
   
※ 설치 전 사전에 설치되어 있어야 하는 프로그램<br>
- install git
<pre>    
sudo apt-get update
sudo apt-get install -y git      
</pre>

- install python
<pre>         
    sudo apt-get install python-keystoneclient
</pre>    
       

# 3.  docker 설치  <div id='3.'/>
- Docker Key 등록
<pre>       
 $ sudo apt update
 $ sudo apt install apt-transport-https ca-certificates curl software-properties-common
 $ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add –
</pre>     

- Docker repository 정보 등록
<pre>
    $ sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable
    $ sudo apt update
    $ apt-cache policy docker-ce
</pre>    
    
- Docker 설치
<pre>  
    $ sudo systemctl status docker
</pre> 

- Docker 설치 확인
<pre>  
    $ sudo apt install docker-ce
    ...
    docker.service - Docker Application Container Engine
    Loaded: loaded (/lib/systemd/system/docker.service; enabled; vendor preset: enabled)
    Active: active (running) since Mon 2019-06-17 01:40:41 UTC; 11s ago
       Docs: https://docs.docker.com
    Main PID: 3821 (dockerd)
      Tasks: 10
     CGroup: /system.slice/docker.service
               └─3821 /usr/bin/dockerd -H fd:/ --containerd=/run/containerd/containerd.sock
    ...
</pre>      
    
- Docker-Compose 설치
<pre>  
    $ sudo apt install docker-compose
</pre>     

# 4.  Monasca-Docker 설치  <div id='4.'/>
- Openstack Keyston network route open
<pre>    
    $ sudo route add -net 172.31.30.0/24 gw 10.0.201.254
</pre>    
    
- Monasa-Docker 설치파일 다운로드
<pre>  
    $ mkdir workspace & cd workspace
    $ git clone https://github.com/monasca/monasca-docker.git
</pre>

- Monasa-Docker docker-compose.yml 파일 변경 
<pre>  
    $ cd monasca-docker
    $ vi docker-compose.yml
    ...
    version: '3'
    services:
    
      memcached:
        image: memcached:${MEMCACHED_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=memcached"
    
      influxdb:
        image: influxdb:${INFLUXDB_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=influxdb"
        ports:
          - "8086:8086"
      influxdb-init:
        image: monasca/influxdb-init:${INFLUXDB_INIT_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=influxdb-init"
        depends_on:
          - influxdb
    
      # cadvisor will allow host metrics to be collected, but requires significant
      # access to the host system
      # if this is not desired, the following can be commented out, and the CADVISOR
      # environment variable should be set to "false" in the `agent-collector`
      # block - however no metrics will be collected
      cadvisor:
        image: google/cadvisor:${CADVISOR_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=cadvisor"
        volumes:
          - "/:/rootfs:ro"
          - "/var/run:/var/run:rw"
          - "/sys:/sys:ro"
          - "/var/lib/docker:/var/lib/docker:ro"
    
      agent-forwarder:
        image: monasca/agent-forwarder:${MON_AGENT_FORWARDER_VERSION}
        environment:
          NON_LOCAL_TRAFFIC: "true"
          LOGSTASH_FIELDS: "service=monasca-agent-forwarder"
          OS_AUTH_URL: http://{OS_AUTH_IP}:25000/v3
          OS_USERNAME: 
          OS_PASSWORD: 
          OS_PROJECT_NAME: 
        extra_hosts:
          - "monasca:192.168.0.103"
          - "control:192.168.56.103"
          - "compute:192.168.56.102"
          - "compute2:192.168.56.101"
          - "compute3:192.168.56.104"
    
      agent-collector:
        image: monasca/agent-collector:${MON_AGENT_COLLECTOR_VERSION}
        restart: on-failure
        environment:
          AGENT_HOSTNAME: "docker-host"
          FORWARDER_URL: "http://agent-forwarder:17123"
          CADVISOR: "true"
          CADVISOR_URL: "http://cadvisor:8080/"
          LOGSTASH_FIELDS: "service=monasca-agent-collector"
          MONASCA_MONITORING: "true"
          MONASCA_LOG_MONITORING: "false"
          OS_AUTH_URL: http://{OS_AUTH_IP}:25000/v3
          OS_USERNAME: <
          OS_PASSWORD:  
          OS_PROJECT_NAME: 
        cap_add:
          - FOWNER
        volumes:
          - "/:/rootfs:ro"
        extra_hosts:
          - "control:192.168.56.103"
          - "compute:192.168.56.102"
          - "compute2:192.168.56.101"
          - "compute3:192.168.56.104"
    
      alarms:
        image: monasca/alarms:${MON_ALARMS_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=monasca-alarms"
          OS_AUTH_URL: http://{OS_AUTH_IP}:25000/v3
          OS_USERNAME: 
          OS_PASSWORD: 
          OS_PROJECT_NAME: 
        depends_on:
    #      - keystone
          - monasca
        extra_hosts:
          - "control:192.168.56.103"
          - "compute:192.168.56.102"
          - "compute2:192.168.56.101"
          - "compute3:192.168.56.104"
    
      zookeeper:
        image: zookeeper:${ZOOKEEPER_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=zookeeper"
        restart: on-failure
    
      kafka:
        image: monasca/kafka:${MON_KAFKA_VERSION}
        environment:
          KAFKA_DELETE_TOPIC_ENABLE: "true"
          LOGSTASH_FIELDS: "service=kafka"
        restart: on-failure
        depends_on:
          - zookeeper
      kafka-watcher:
        image: monasca/kafka-watcher:${MON_KAFKA_WATCHER_VERSION}
        environment:
          BOOT_STRAP_SERVERS: "kafka"
          PROMETHEUS_ENDPOINT: "0.0.0.0:8080"
          LOGSTASH_FIELDS: "service=kafka-watcher"
        depends_on:
          - kafka
        ports:
          - "18080:8080"
      kafka-init:
        image: monasca/kafka-init:${MON_KAFKA_INIT_VERSION}
        environment:
          ZOOKEEPER_CONNECTION_STRING: "zookeeper:2181"
          KAFKA_TOPIC_CONFIG: segment.ms=900000 # 15m
          KAFKA_CREATE_TOPICS: "\
            metrics:64:1,\
            alarm-state-transitions:12:1,\
            alarm-notifications:12:1,\
            retry-notifications:3:1,\
            events:12:1,\
            kafka-health-check:1:1,\
            60-seconds-notifications:3:1"
          LOGSTASH_FIELDS: "service=kafka-init"
        depends_on:
          - zookeeper
    
      mysql:
        image: mysql:${MYSQL_VERSION}
        environment:
          MYSQL_ROOT_PASSWORD: secretmysql
          LOGSTASH_FIELDS: "service=mysql"
        ports:
          - "3306:3306"
      mysql-init:
        image: monasca/mysql-init:${MYSQL_INIT_VERSION}
        environment:
          MYSQL_INIT_DISABLE_REMOTE_ROOT: "false"
          MYSQL_INIT_RANDOM_PASSWORD: "false"
          LOGSTASH_FIELDS: "service=mysql-init"
    
    #  keystone 부분 주석 처리
    #  keystone:
    #    image: monasca/keystone:${MON_KEYSTONE_VERSION}
    #    environment:
    #      KEYSTONE_HOST: keystone
    #      KEYSTONE_PASSWORD: secretadmin
    #      KEYSTONE_DATABASE_BACKEND: mysql
    #      KEYSTONE_MYSQL_HOST: mysql
    #      KEYSTONE_MYSQL_USER: keystone
    #      KEYSTONE_MYSQL_PASSWORD: keystone
    #      KEYSTONE_MYSQL_DATABASE: keystone
    #      LOGSTASH_FIELDS: "service=keystone"
    #    depends_on:
    #      - mysql
    #    ports:
    #      - "5001:5000"
    #      - "35357:35357"
    
      monasca-sidecar:
        image: timothyb89/monasca-sidecar:${MON_SIDECAR_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=monasca-sidecar"
    
      monasca:
        image: monasca/api:${MON_API_VERSION}
        environment:
          SIDECAR_URL: http://monasca-sidecar:4888/v1/ingest
          LOGSTASH_FIELDS: "service=monasca-api"
          KEYSTONE_IDENTITY_URI: http://{KEYSTONE_IP}:25000/v3
          KEYSTONE_AUTH_URI: http://{KEYSTONE_IP}:25000/v3
          KEYSTONE_ADMIN_USER: 
          KEYSTONE_ADMIN_PASSWORD: 
        depends_on:
          - influxdb
    #      - keystone
          - mysql
          - zookeeper
          - kafka
          - monasca-sidecar
          - memcached
        ports:
          - "8070:8070"
        extra_hosts:
          - "control:192.168.56.103"
          - "compute:192.168.56.102"
          - "compute2:192.168.56.101"
          - "compute3:192.168.56.104"
    
      monasca-persister:
        image: monasca/persister:${MON_PERSISTER_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=monasca-persister"
        restart: on-failure
        depends_on:
          - monasca
          - influxdb
          - zookeeper
          - kafka
    
      thresh:
        image: monasca/thresh:${MON_THRESH_VERSION}
        environment:
          NO_STORM_CLUSTER: "true"
          WORKER_MAX_HEAP_MB: "256"
          LOGSTASH_FIELDS: "service=monasca-thresh"
        depends_on:
          - zookeeper
          - kafka
    
      monasca-notification:
        image: monasca/notification:${MON_NOTIFICATION_VERSION}
        environment:
          NF_PLUGINS: "webhook"
          LOGSTASH_FIELDS: "service=monasca-notification"
          STATSD_HOST: monasca-statsd
          STATSD_PORT: 8125
        depends_on:
          - monasca
          - zookeeper
          - kafka
          - mysql
    
      grafana:
        image: monasca/grafana:${MON_GRAFANA_VERSION}
        environment:
          GF_AUTH_BASIC_ENABLED: "false"
          GF_USERS_ALLOW_SIGN_UP: "true"
          GF_USERS_ALLOW_ORG_CREATE: "true"
          GF_AUTH_KEYSTONE_ENABLED: "true"
          GF_AUTH_KEYSTONE_AUTH_URL: http://{KEYSTONE_IP}:25000
          GF_AUTH_KEYSTONE_VERIFY_SSL_CERT: "false"
          GF_AUTH_KEYSTONE_DEFAULT_DOMAIN: "Default"
          LOGSTASH_FIELDS: "service=grafana"
        ports:
          - "3000:3000"
        depends_on:
    #      - keystone
          - monasca
        extra_hosts:
            - "control:192.168.56.103"
            - "compute:192.168.56.102"
            - "compute2:192.168.56.101"
            - "compute3:192.168.56.104"
    
      grafana-init:
        image: monasca/grafana-init:${MON_GRAFANA_INIT_VERSION}
        environment:
          LOGSTASH_FIELDS: "service=grafana-init"
        depends_on:
          - grafana
    
      monasca-statsd:
        image: monasca/statsd:${MON_STATSD_VERSION}
        environment:
          FORWARDER_URL: http://agent-forwarder:17123
          LOG_LEVEL: WARN
        ports:
          - "8125/udp"

    ...
</pre>
    
- Monasca-Docker Server 설치 및 시작
<pre>    
    $ sudo docker-compose up -d
</pre>
![](images/Monasca/monasca-docker-ps.png)

# 5. Elasticserarch 서버 설치  <div id='5.'/>
- dependencies 설치
<pre>    
    $ sudo apt-get update
    $ sudo apt-get install openjdk-8-jdk
</pre>

- Elasticsearch repository 등록
<pre>    
    $ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -
    $ echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-5.x.list
</pre>

- Elasticsearch 설치
<pre>
    $ sudo apt-get update
    $ sudo apt-get install -y elasticsearch
</pre>     
    
- 사용자 그룹 추가 - Elasticsearch
<pre>    
    $ sudo usermod -a -G elasticsearch “사용자 계정”
</pre>        
    
- Elasticsearch configuration 파일 수정

<pre>    
    $ cd /etc/elasticsearch && sudo vi elasticsearch.yml
    ---
    ...
    # Lock the memory on startup:
    bootstrap.memory_lock: true
    ...
    # Set the bind address to a specific IP (IPv4 or IPv6):
    network.host: 0.0.0.0
    
    # Set a custom port for HTTP:
    http.port: 9200
    ...
</pre>
    
- Elasticsearch service 파일 수정

<pre>    
    $ sudo vi /usr/lib/systemd/system/elasticsearch.service
    ...
    # Specifies the maximum number of bytes of memory that may be locked into RAM
    # Set to "infinity" if you use the 'bootstrap.memory_lock: true' option
    # in elasticsearch.yml and 'MAX_LOCKED_MEMORY=unlimited' in /etc/default/elasticsearch
    LimitMEMLOCK=infinity
    ...
</pre>

- Elasticsearch default 파일 수정

<pre>
    $ sudo vi /etc/default/elasticsearch
    ...
    # The maximum number of bytes of memory that may be locked into RAM
    # Set to "unlimited" if you use the 'bootstrap.memory_lock: true' option
    # in elasticsearch.yml.
    # When using Systemd, the LimitMEMLOCK property must be set
    # in /usr/lib/systemd/system/elasticsearch.service
    MAX_LOCKED_MEMORY=unlimited
    ...
</pre>    

- Elasticsearch 서비스 시작
<pre>    
    $ sudo service elasticsearch start
</pre>
    
- Elasticserarch 서버 가동 여부 확인
<pre>    
    $ netstat -plntu | grep 9200
</pre>
![](images/Monasca/monasca-elasticsearch-ps.png)

- mlockall 정보가 “enabled” 되었는지 확인
<pre>    
    $ curl -XGET 'localhost:9200/_nodes?filter_path=**.mlockall&pretty'
</pre>
![](images/Monasca/monasca-elasticsearch-mlockall.png)
    

# 6.  logstash 설치  <div id='6.'/>
- logstash 설치
<pre>    
    $ sudo apt-get install -y logstash
</pre>

- /etc/hosts 파일 수정
<pre>    
    $ sudo vi /etc/hosts
    ---
     ...
    “private network ip”  “hostname”
    ex) 192.168.0.103   host logstash elasticsearch
     ...
</pre>

- SSL certificate 파일 생성
<pre>
    $ cd /etc/logstash
    $ sudo openssl req -subj /CN=”hostaname” -x509 -days 3650 -batch -nodes -newkey rsa:4096 -keyout logstash.key -out logstash.crt
</pre>            

- filebeat-input.conf 파일 생성
<pre>
    $ cd /etc/logstash
    $ sudo vi conf.d/filebeat-input.conf
    ---
    ...
    input {
       beats {
         port => 5443
         type => syslog
         ssl => true
         ssl_certificate => "/etc/logstash/logstash.crt"
         ssl_key => "/etc/logstash/logstash.key"
       }
    }
    ...
</pre>

- syslog-filter.conf 파일 생성
<pre>
    $ cd /etc/logstash
    $ sudo vi conf.d/syslog-filter.conf
    ---
    ...
    filter {
          if [type] == "syslog" {
            grok {
              match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{SYSLOGHOST:syslog_hostname} %{DATA:syslog_program}(?:\[%{POSINT:syslog_pid}\])?: %{GREEDYDATA:syslog_message}" }
              add_field => [ "received_at", "%{@timestamp}" ]
              add_field => [ "received_from", "%{host}" ]
            }
            date {
              match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
            }
          }
        }
    ...
</pre>

- output-elasticsearch.conf 파일 생성
<pre>
    $ cd /etc/logstash
    $ sudo vi conf.d/output-elasticsearch.conf
    ---
    ...
    output {
          elasticsearch { hosts => ["”your elastic ip”:9200"]    # 설치된 환경의 IP 정보
            hosts => "”your elastic ip”:9200"                 # 설치된 환경의 IP 정보
            manage_template => false
            index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
            document_type => "%{[@metadata][type]}"
          }
        }    
    ...
</pre>

- logstash 서비스 시작
<pre>
    $ sudo service logstash start
</pre>

- logstash 서비스 확인
<pre>
    $ sudo service logstash start
</pre>
![](images/Monasca/monasca-logstash-ps.png)

# 14. Reference : Cross-Project(Tenant) 사용자 추가 및 권한 부여  <div id='14.'/>
Openstack 기반으로 생성된 모든 Project(Tenant)의 정보를 하나의 계정으로 수집 및 조회하기 위해서는 Cross-Tenant 사용자를 생성하여, 각각의 Project(Tenant)마다 조회할 수 있도록 멤버로 등록한다.
Openstack Cli를 이용하여 Cross-Tenant 사용자를 생성한 후, Openstack Horizon 화면으로 통해 각각의 프로젝트 사용자 정보에 생성한 Cross-Tenant 사용자 및 권한을 부여한다.
1. Cross-Tenant 사용자 생성
<pre>    
    $ openstack user create --domain default --password-prompt monasca-agent
    $ openstack role create monitoring-delegate
</pre>    
    
2. Project 사용자 추가
![](images/Monasca/14.1.png)
각각의 프로젝트 멤버관리에 추가한 Cross-Tenant 사용자 정보를 등록한다.
![](images/Monasca/14.2.png)
![](images/Monasca/14.3.png)
추가한 Cross-Tenant 사용자를 선택 후, 생성한 Role을 지정한다.