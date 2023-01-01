from PKS import PKS
import psycopg2
import psycopg2.extras
import dpkt
from dpkt.udp import UDP
from dpkt.tcp import TCP
import datetime
from dotenv import load_dotenv
import os
import socket
from string import Template
import pandas as pd
from time import perf_counter
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn import preprocessing, cluster, model_selection
import sklearn
from scipy.spatial.distance import cdist
import numpy as np

query_create_table = Template('CREATE TABLE IF NOT EXISTS $table_name ('
                              'packet_id integer,'
                              'timestamp_epoch decimal,'
                              'timestamp_real timestamp,'
                              'length smallint,'
                              'ip_src cidr,'
                              'ip_dst cidr,'
                              'port_src integer,'
                              'port_dst integer,'
                              'protocol varchar(32))')


# Функция готовит чистую таблицу для загрузки данных дампа
def prepareDB(cursor):
    cursor.execute('DROP TABLE IF EXISTS imports')
    cursor.execute(query_create_table.substitute(table_name='imports'))
    conn.commit()


# Функция проводит парсинг каждого пакета и возвращает экземпляр класса PKS
def getPacketStructure(ts, frame):
    global src_ip
    global dst_ip
    global src_port
    global dst_port
    global protocol
    eth = dpkt.ethernet.Ethernet(frame)
    timestamp = ts
    timestamp_real = datetime.datetime.fromtimestamp(ts)
    if isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data
        src_ip = socket.inet_ntoa(ip.src)
        dst_ip = socket.inet_ntoa(ip.dst)
        if isinstance(ip.data, UDP) or isinstance(ip.data, TCP):
            transport = ip.data
            src_port = transport.sport
            dst_port = transport.dport
            protocol = "UDP" if ip.p == 17 else "TCP"
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            src_port, dst_port = 0, 0
            protocol = "ICMP"
    else:
        return False
    pkt = PKS(timestamp, timestamp_real, len(frame), src_ip, dst_ip, src_port, dst_port, protocol)
    return pkt


# Функция загружает созданный экземпляр класса в базу данных
def uploadStructure(cursor, frame, pack_id):
    query = "INSERT INTO imports (packet_id, timestamp_epoch, timestamp_real, length, ip_src,ip_dst, port_src, port_dst, protocol) values (%s, %s,%s,%s,%s,%s,%s,%s,%s)"
    cursor.execute(query, (
        pack_id, frame.timestamp_epoch, frame.timestamp_real, frame.length, frame.ip_src, frame.ip_dst, frame.port_src,
        frame.port_dst, frame.protocol,))
    conn.commit()


# Функция создает таблицы с сессиями и наполняет их
def createSessionsTable(cur):
    sessions = dict()
    query = "SELECT distinct ip_src, ip_dst, port_src, port_dst FROM imports order by port_src asc"
    cur.execute(query)
    res = cur.fetchall()
    id1 = 0
    for item in res:
        sessions[id1] = item
        id1 += 1
    conn.commit()
    query2 = "SELECT * FROM imports"
    cur.execute(query2)
    row = cur.fetchone()
    num = 0
    while row is not None:
        conn2 = psycopg2.connect(
            database=os.getenv("DATABASE"),
            user=os.getenv("DB_USER"),
            password=os.getenv("PASSWORD"),
            host=os.getenv("HOST"),
            port=os.getenv("PORT")
        )
        cur2 = conn2.cursor()
        item = tuple(row[4:8])
        pack_id2 = 1
        for key, value in sessions.items():
            if item == value:
                name_table = "session_" + str(key)
                query = query_create_table.substitute(table_name=name_table)
                cur2.execute(query)
                query = f"INSERT INTO {name_table} (packet_id, timestamp_epoch, timestamp_real, length, ip_src,ip_dst, port_src, port_dst, protocol) values (%s,%s,%s,%s,%s,%s,%s,%s,%s)"
                pack_id2+=1
                cur2.execute(query, row)
                conn2.commit()
                break
        num += 1
        print(num)
        row = cur.fetchone()


# Дебаг-функция для удаления всех session-таблиц
def dropTables():
    conn3 = psycopg2.connect(
        database=os.getenv("DATABASE"),
        user=os.getenv("DB_USER"),
        password=os.getenv("PASSWORD"),
        host=os.getenv("HOST"),
        port=os.getenv("PORT")
    )
    cursor3 = conn3.cursor()
    for i in range(650):
        cursor3.execute(f"DROP TABLE IF exists session_{i}")
        conn3.commit()


# Функция создает таблицу-датасет для последующей обработки данных
def createDataSet():
    delay = 60
    conn4 = psycopg2.connect(
        database=os.getenv("DATABASE"),
        user=os.getenv("DB_USER"),
        password=os.getenv("PASSWORD"),
        host=os.getenv("HOST"),
        port=os.getenv("PORT")
    )
    cursor4 = conn4.cursor()
    query = "DROP TABLE IF EXISTS dataset"
    cursor4.execute(query)
    query2 = "CREATE TABLE IF NOT EXISTS dataset (" \
             "   session_id SERIAL," \
             "   packets_amount integer," \
             "   packets_size_all integer," \
             "   packets_size_avg decimal," \
             "   packets_size_dis decimal," \
             "   avg_time_between decimal," \
             "   avg_time_disp decimal)"
    cursor4.execute(query2)
    query_count_tables = "SELECT count(table_name) FROM information_schema. tables WHERE table_schema NOT IN ('information_schema','pg_catalog')"
    cursor4.execute(query_count_tables)
    conn4.commit()
    amount = int(cursor4.fetchone()[0]) - 2
    for session_id in range(amount):
        avgs_time = []
        query = f"select count(*),sum(length), avg(length),var_pop(length) from session_{session_id}"
        cursor4.execute(query)
        conn4.commit()
        amount, sum_packets, avg_packets, disp_packets = cursor4.fetchone()
        query = f"select * from session_{session_id} order by timestamp_real"
        cursor4.execute(query)
        if amount > 1:
            time1 = cursor4.fetchone()[1]
            for packet in range(amount-1):
                time2 = cursor4.fetchone()[1]
                if time2-time1 <= delay:
                    avgs_time.append(time2-time1)
                    time1 = time2
                else:
                    time1 = time2
            if len(avgs_time) != 0:
                avg_time_packets = sum(avgs_time)/len(avgs_time)
                disp_time_packets = sum((time-avg_time_packets)**2 for time in avgs_time) / len(avgs_time)
            else:
                avg_time_packets = 0
                disp_time_packets = 0
        else:
            avg_time_packets = 0
            disp_time_packets = 0
        query = "INSERT INTO dataset (session_id, packets_amount, packets_size_all, packets_size_avg, packets_size_dis, avg_time_between, avg_time_disp) " \
                "values (%s,%s,%s,%s,%s,%s,%s)"
        cursor4.execute(query, [session_id, amount, sum_packets, round(avg_packets, 3) , round(disp_packets, 3), round(avg_time_packets, 3), round(disp_time_packets, 3)])
        conn4.commit()
    conn4.close()


def exportToCSV(cursor):
    query = "select session_id, packets_amount, packets_size_all, packets_size_avg, packets_size_dis, avg_time_between, avg_time_dist from dataset"
    cursor.execute(query)
    tuples_list = cursor.fetchall()
    columns_names = ["session_id", "packets_amount", "packets_size_all", "packets_size_avg", "packets_size_dis", "avg_time_between", "avg_time_dis"]
    df = pd.DataFrame(tuples_list, columns=columns_names)
    df.to_csv("exportDataset.csv", index=False)


if __name__ == "__main__":
    load_dotenv()                                               # Загрузка env переменных
    conn = psycopg2.connect(                                    # Подключение к базе данных
        database=os.getenv("DATABASE"),
        user=os.getenv("DB_USER"),
        password=os.getenv("PASSWORD"),
        host=os.getenv("HOST"),
        port=os.getenv("PORT")
    )
    cursor = conn.cursor()
    prepareDB(cursor)                                         # Создание таблицы imports

    f = open('ddos2.pcap', 'rb')                              # Чтение pcap-файла
    pcap = dpkt.pcap.Reader(f)

    packs = []
    flag = 0
    pack_id = 1
    for ts, buf in pcap:                                      # Загрузка структуры пакетов в БД
        pack = getPacketStructure(ts, buf)
        if pack is not False:
            uploadStructure(cursor, pack, pack_id)
            pack_id+=1
        else:
            continue

    dropTables()

    createSessionsTable(cursor)                               # Создание таблиц с сессиями

    createDataSet()                                           # Создание таблицы с итоговым датасетом

    exportToCSV(cursor)                                       # Экспортирует данные в CSV

    tuples = pd.read_csv("exportDataset.csv", delimiter=',')
    scaler = preprocessing.MinMaxScaler()                     # Нормализация данных
    column_names = tuples.columns
    tuples[column_names[1:]] = scaler.fit_transform(tuples[column_names[1:]])
    scaled_df = pd.DataFrame(tuples, columns=column_names)
    X_train, X_test = model_selection.train_test_split(tuples, train_size=0.7)
    X_train.to_csv("x_train.csv", index=False)                # Разделение на обучающую и тестовую выборки
    X_test.to_csv("x_test.csv", index=False)


    clusters_amount = 4
    kmeans = cluster.KMeans(n_clusters=clusters_amount, init='random', n_init=10, max_iter=1000, random_state=0)
    kmeans.fit_predict(X_train[column_names[1:]])
    kmeans.fit_predict(X_test[column_names[1:]])
    details = [(packet, cluster) for packet, cluster in zip(X_test["session_id"], kmeans.labels_)]
    attacks = [1, 162, 163, 164, 165, 166, 167, 168, 169, 170,
               171, 172, 173, 174, 175, 176, 177, 178, 179, 180,
               181, 182, 183, 184, 185, 186, 187]
    test_attacks = 0
    for item in details:
        if item[0] in attacks:
            print(f"!!!!!!!!!!Сессия №{item[0]} - Кластер {item[1]} !!!!!!!!!!")
            test_attacks+=1
        else:
            print(f"Сессия №{item[0]} - Кластер {item[1]}")

    for i in range(len(kmeans.cluster_centers_)):
        print(f"Количество элементов в кластере {i} -  {kmeans.labels_.tolist().count(i)}\n")
    print(f"Количество атак в тестовой выборке - {test_attacks}")
    x_axis = [str(i) for i in range(0, clusters_amount)]
    x_axis.append("Attack")
    y_axis = [kmeans.labels_.tolist().count(i) for i in range(0, clusters_amount)]
    y_axis.append(test_attacks)
    plot = plt.bar(x_axis,y_axis, color=['red', 'green', 'blue', 'orange', 'cyan', 'purple', 'gray', 'olive', 'black', 'pink'])
    for value in plot:
        height = value.get_height()
        plt.text(value.get_x() + value.get_width() / 2., 1.002 * height, '%d' % int(height), ha='center', va='bottom')
    plt.show()
    conn.close()
