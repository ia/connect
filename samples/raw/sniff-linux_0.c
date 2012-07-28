#include <net/if.h>

#include <stdio.h>
#include <signal.h>
#include <string.h>

#include <sys/socket.h>

#include <linux/socket.h>
#include <linux/ioctl.h>
//#include <linux/if.h>
#include <linux/in.h>
#include <linux/types.h>

#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#include <sys/ioctl.h>

/*
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/types.h>
*/


#ifndef SIOCGIFCONF
	#include <sys/sockio.h>
#endif

#define PROMISC_MODE_ON 1 // флаг включения неразборчивый режим
#define PROMISC_MODE_OFF 0 // флаг выключения неразборчивого режима

struct ifparam {
    __u32 ip;	// IP адрес
    __u32 mask;	// маска подсети
    int mtu;	// размер MTU
    int index;	// индекс интерфейса
} ifp;


int getifconf(__u8 *intf, struct ifparam *ifp, int mode)
{
    int fd;
    struct sockaddr_in s;
    struct ifreq ifr; // см. <linux/if.h>

    memset((void *)&ifr, 0, sizeof(struct ifreq));
    if((fd = socket(AF_INET,SOCK_DGRAM,0)) < 0)	return (-1);

    sprintf(ifr.ifr_name,"%s",intf);

/*
 * Проверяем флаг режима. Если он установлен в 0, неразборчивый режим
 * необходимо отключить, поэтому сразу выполняется переход на метку setmode
 */
    if(!mode) goto setmode;

/*
 * Определяем IP адрес сетевого интерфейса
 */
    if(ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
	perror("ioctl SIOCGIFADDR");
	return -1;
    }
    memset((void *)&s, 0, sizeof(struct sockaddr_in));
    memcpy((void *)&s, (void *)&ifr.ifr_addr, sizeof(struct sockaddr));
    memcpy((void *)&ifp->ip, (void *)&s.sin_addr.s_addr, sizeof(__u32));

/*
 * Определяем маску подсети
 */
    if(ioctl(fd, SIOCGIFNETMASK, &ifr) < 0) {
	perror("ioctl SIOCGIFNETMASK");
	return -1;
    }
    memset((void *)&s, 0, sizeof(struct sockaddr_in));
    memcpy((void *)&s, (void *)&ifr.ifr_netmask, sizeof(struct sockaddr));
    memcpy((void *)&ifp->mask, (void *)&s.sin_addr.s_addr, sizeof(u_long));

/*
 * Определяем размер MTU
 */
    if(ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
	perror("ioctl SIOCGIFMTU");
	return -1;
    }
    ifp->mtu = ifr.ifr_mtu;

/*
 * Индекс интерфейса
 */
    if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
	perror("ioctl SIOCGIFINDEX");
	return -1;
    }
    ifp->index = ifr.ifr_ifindex;


/*
 * Устанавливаем заданный режим работы сетевого интерфейса
 */
setmode:

/*
 * Получаем значение флагов
 */
    if(ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
	perror("ioctl SIOCGIFFLAGS");
	close(fd);
	return -1;
    }

/*
 * В зависимости от значения третьего параметра функции, устанавливаем
 * или снимаем флаг неразборчивого режима
 */
    if(mode) ifr.ifr_flags |= IFF_PROMISC;
    else ifr.ifr_flags &= ~(IFF_PROMISC);

/*
 * Устанавливаем новое значение флагов интерфейса
 */
    if(ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
	perror("ioctl SIOCSIFFLAGS");
	close(fd);
	return (-1);
    }

    return 0;
}

int getsock_recv(int index)
{
    int sd; // дескриптор сокета
/*
 * При работе с пакетными сокетами для хранения адресной информации
 * сетевого интерфейса вместо структуры sockaddr_in используется структура
 * sockaddr_ll (см. <linux/if_packet.h>)
 */
    struct sockaddr_ll s_ll;

/*
 * Cоздаем пакетный сокет. Т.к. MAC-адреса мы тоже собираемся обрабатывать,
 * параметр type системного вызова socket принимает значение SOCK_RAW
 */
    sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sd < 0) return -1;

    memset((void *)&s_ll, 0, sizeof(struct sockaddr_ll));

/*
 * Заполним поля адресной структуры s_ll
 */
    s_ll.sll_family = PF_PACKET; // тип сокета
    s_ll.sll_protocol = htons(ETH_P_ALL); // тип принимаемого протокола
    s_ll.sll_ifindex = index; // индекс сетевого интерфейса

/*
 * Привязываем сокет к сетевому интерфейсу. В принципе, делать это не
 * обязательно, если на хосте активен только один сетевой интерфейс.
 * При наличии двух и более сетевых плат пакеты будут приниматься сразу со всех
 * активных интерфейсов, и если нас интересуют пакеты только из одного сегмента
 * сети, целесообразно выполнить привязку сокета к нужному интерфейсу
 */
    if(bind(sd, (struct sockaddr *)&s_ll, sizeof(struct sockaddr_ll)) < 0) {
	close(sd);
	return -1;
    }

    return sd;
}


/*
 * В буфере buff будут сохранятся принятые сетевые пакеты.
 * Значение ETH_FRAME_LEN равно максимальной длине кадра Ethernet (1514)
 * и определено в <linux/if_ether.h>
 */
 __u8 buff[ETH_FRAME_LEN];

/*
 * Функция, которая заменит стандартный обработчик сигнала SIGINT.
 * Задача этой функции - по приходу сигнала SIGINT вывести интерфейс из
 * состояния "Promiscuous mode" в обычный режим
 */
void mode_off()
{
    if(getifconf("eth0", &ifp, PROMISC_MODE_OFF) < 0) {
	perror("getifconf");
	exit(-1);
    }

    return;
}

/*
 * Главная функция
 */
int main()
{
    __u32 num = 0;
    int eth0_if, rec = 0, ihl = 0;
    struct iphdr ip; // структура для хранения IP заголовка пакета
    struct tcphdr tcp; // TCP заголовок
    struct ethhdr eth; // заголовок Ethernet-кадра
    static struct sigaction act;

/*
 * Получаем параметры сетевого интерфейса eth0 и переводим его
 * в неразборчивый режим
 */
    if(getifconf("wlan0", &ifp, PROMISC_MODE_ON) < 0) {
	perror("getifconf");
	return -1;
    }

/*
 * Отобразим полученные параметры сетевого интерфейса
 */
    printf("IP адрес - %s\n",inet_ntoa(ifp.ip));
    printf("Маска подсети - %s\n",inet_ntoa(ifp.mask));
    printf("MTU - %d\n", ifp.mtu);
    printf("Индекс - %d\n", ifp.index);

/*
 * Получим дескриптор пакетного сокета
 */
    if((eth0_if = getsock_recv(ifp.index)) < 0) {
	perror("getsock_recv");
	return -1;
    }

/*
 * Определим новый обработчик сигнала SIGINT - функцию mode_off
 */
    act.sa_handler = mode_off;
    sigfillset(&(act.sa_mask));
    sigaction(SIGINT, &act, NULL);

/*
 * Запускаем бесконечный цикл приема пакетов
 */
    for(;;) {

	memset(buff, 0, ETH_FRAME_LEN);
	
	rec = recvfrom(eth0_if, (char *)buff, ifp.mtu + 18, 0, NULL, NULL);
	if(rec < 0 || rec > ETH_FRAME_LEN) {
	    perror("recvfrom");
	    return -1;
	}

	memcpy((void *)&eth, buff, ETH_HLEN);
	memcpy((void *)&ip, buff + ETH_HLEN, sizeof(struct iphdr));
	if((ip.version) != 4) continue;
	memcpy((void *)&tcp, buff + ETH_HLEN + ip.ihl * 4, sizeof(struct tcphdr));

/*
 * MAC-адреса отправителя и получателя
 */
	printf("\n%u\n", num++);
	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\t->\t",
	eth.h_source[0],eth.h_source[1],eth.h_source[2],
	eth.h_source[3],eth.h_source[4],eth.h_source[5]);

	printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
	eth.h_dest[0],eth.h_dest[1],eth.h_dest[2],
	eth.h_dest[3],eth.h_dest[4],eth.h_dest[5]);

	printf("Длина заголовка - %d, ", (ip.ihl * 4));
	printf("длина пакета - %d\n", ntohs(ip.tot_len));

/*
 * Если транспортный протокол - TCP, отобразим IP адреса и порты
 * получателя и отправителя
 */
	if(ip.protocol == IPPROTO_TCP) {
	    printf("%s (%d)\t->\t",inet_ntoa(ip.saddr), ntohs(tcp.source));
	    printf("%s (%d)\n",inet_ntoa(ip.daddr), ntohs(tcp.dest));
	    printf("TCP пакет\n");
	}
    }

    return 0;
}

