# Benchmark
初期状態(workload=1):
初期状態(workload=4):
phpソース変更(workload=1):
phpソース変更(workload=4):
phpソース以外も変更(workload=1):
phpソース以外も変更(workload=4):
phpソース以外も変更(workload=24):

# 変更点
## PHPソースの変更点
まず,このPHPソースでは,limonadeというフレームワークが使われていて,
URLにより関数をdispatchしていた.
これが遅いのではないかと思い,
フレームワークを使わないような設計に変更した.
また,
==演算子はキャストが発生し,
セキュリティ的にも速度的にも問題が生じるため,
===演算子を利用するように変更した.

## 全変更点
### DB関係の変更点
使用しているEC2のインスタンスがxlargeと余裕があったため,
メモリを使用するような設定に変更した.
以下に変更した設定を記す.
max_connections=100
thread_cache=100
innodb_additional_mem_pool_size = 32M
innodb_buffer_pool_size = 8G
innodb_log_buffer_size = 64MB
join_buffer_size = 256K
read_buffer_size = 256K
read_rnd_buffer_size = 2M
sort_buffer_size = 4M
query_cache_limit = 16M
query_cache_size = 512M
query_cache_type = 1

全てのSQLの実行時間をslow_logを用いてダンプした.
そしてmysqldumpslowでボトルネックとなっているSQLを探すと,
user_locked,ip_bannedに利用するSQLが遅いことが分かった.
SQL命令のexplainを使ってみると,
主命令部分でフルインデックススキャンをしていて,
遅くなっていることが分かったので,
login_log.user_idとlogin_log.ipにインデックスを設定した.
logのInsertが遅くなったが,
再びmysqldumpslowで確認すると,さきほど2つのSQLの実行時間合計よりは高速化できていて,
また他のSQLも高速化できていたので,これ以上のSQLの高速化は諦めることとした.

### PHPの設定関係
まず,今回ログイン処理を高速化するため,
セッションの管理が重要となる.
そのため,memcachedを利用し,セッションをメモリ上に保存している.
また,UNIX domain socketを利用することでオーバーヘッドを減らした.
加えて,php-fpmのworkerの数など,またこれもUNIX domain socketを利用するように変更した.
以下に変更した設定を記す.
pm = static
pm.max_children = 16
pm.process_idle_timeout = 10s;
pm_max_requests = 1024;

### nginxの設定関係
CPUは4threadsで動作するため,
worker_processesを4に設定した.

### Linuxの設定関係
TCPの使用するポートの数が多く,
すぐ使いきってしまうため,
再利用するよう設定を変更した.
以下に変更した設定を記す.
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.ip_local_port_range = 1024 65535
