#include "eloop.h"



static struct eloop_data eloop;
static struct dl_list alloc_list = DL_LIST_HEAD_INIT(alloc_list);

void * os_zalloc(size_t size)
{
    void *ptr = os_malloc(size);
    if (ptr)
        os_memset(ptr, 0, size);
    return ptr;
}

void * os_malloc(size_t size)
{
	struct os_alloc_trace *a;

	a = malloc(sizeof(*a) + size);
	if (a == NULL)
		return NULL;
	a->magic = ALLOC_MAGIC;
	dl_list_add(&alloc_list, &a->list);
	a->len = size;

	return a + 1;
}
void os_free(void *ptr)
{
	struct os_alloc_trace *a;

	if (ptr == NULL)
		return;
	a = (struct os_alloc_trace *) ptr - 1;
	if (a->magic != ALLOC_MAGIC) {
		print_debug_log("FREE[%p]: invalid magic 0x%x%s",a, a->magic,a->magic == FREED_MAGIC ? " (already freed)" : "");
		abort();
	}
	dl_list_del(&a->list);
	a->magic = FREED_MAGIC;
	free(a);
}
void *os_realloc(void *ptr,size_t size)
{
	struct os_alloc_trace *a;
	size_t copy_len;
	void *n;

	if( ptr == NULL){
		return os_malloc(size);
	}

	if (ptr == NULL)
		return os_malloc(size);

	a = (struct os_alloc_trace *) ptr - 1;
	if (a->magic != ALLOC_MAGIC) {
		print_debug_log("REALLOC[%p]: invalid magic 0x%x%s",a, a->magic,a->magic == FREED_MAGIC ? " (already freed)" : "");
		abort();
	}
	n = os_malloc(size);
	if (n == NULL)
		return NULL;
	copy_len = a->len;
	if (copy_len > size)
		copy_len = size;
	memcpy(n, a + 1, copy_len);
	os_free(ptr);

	return n;
}


int os_get_reltime(struct os_reltime *t)
{
#if defined(CLOCK_BOOTTIME)
    static clockid_t clock_id = CLOCK_BOOTTIME;
#elif defined(CLOCK_MONOTONIC)
    static clockid_t clock_id = CLOCK_MONOTONIC;
#else
    static clockid_t clock_id = CLOCK_REALTIME;
#endif
    struct timespec ts;
    int res;

    while (1) {
        res = clock_gettime(clock_id, &ts);
        if (res == 0) {
            t->sec = ts.tv_sec;
            t->usec = ts.tv_nsec / 1000;
            return 0;
        }
        switch (clock_id) {
#ifdef CLOCK_BOOTTIME
        case CLOCK_BOOTTIME:
            clock_id = CLOCK_MONOTONIC;
            break;
#endif
#ifdef CLOCK_MONOTONIC
        case CLOCK_MONOTONIC:
            clock_id = CLOCK_REALTIME;
            break;
#endif
        case CLOCK_REALTIME:
            return -1;
        }
    }
}

static inline int os_reltime_before(struct os_reltime *a,
                    struct os_reltime *b)
{
    return (a->sec < b->sec) ||
           (a->sec == b->sec && a->usec < b->usec);
}

static inline void os_reltime_sub(struct os_reltime *a, struct os_reltime *b,
                  struct os_reltime *res)
{
    res->sec = a->sec - b->sec;
    res->usec = a->usec - b->usec;
    if (res->usec < 0) {
        res->sec--;
        res->usec += 1000000;
    }
}

static inline void *os_realloc_array(void *ptr,size_t nmemb,size_t size)
{
	if(size && nmemb >(~(size_t)0/size)){
		return NULL;
	}

	return os_realloc(ptr,nmemb *size);
}


int epoll_init(void)
{
	eloop.epoll_fd = epoll_create1(0);
	if(eloop.epoll_fd <0){
		print_debug_log("%s epoll_create1 failed.%s\n",__FUNCTION__,strerror(errno));
		return -1;
	}

	eloop.readers.type = EVENT_TYPE_READ;
	eloop.writers.type = EVENT_TYPE_WRITE;
	eloop.exceptions.type = EVENT_TYPE_EXCEPTION;

	return 1;
}

static void eloop_sock_table_destroy(struct eloop_sock_table *table)
{
	if (table) {
		int i;
		for (i = 0; i < table->count && table->table; i++) {
			print_debug_log("ELOOP: remaining socket: "
				   "sock=%d eloop_data=%p user_data=%p "
				   "handler=%p",
				   table->table[i].sock,
				   table->table[i].eloop_data,
				   table->table[i].user_data,
				   table->table[i].handler);
		}
		os_free(table->table);
	}
}

void eloop_destroy(void)
{
	eloop_sock_table_destroy(&eloop.readers);
	eloop_sock_table_destroy(&eloop.writers);
	eloop_sock_table_destroy(&eloop.exceptions);
	os_free(eloop.epoll_table);
	os_free(eloop.epoll_events);
	close(eloop.epoll_fd);

}

static int eloop_sock_table_add_sock(struct	eloop_sock_table *table,int sock,eloop_sock_handler handler,void *eloop_data,void *user_data)
{
	struct eloop_sock *temp_table,*tmp;
	struct epoll_event ev,*temp_events;
	int next;
	int new_max_sock;

	if (sock > eloop.max_sock)
		new_max_sock = sock;
	else
		new_max_sock = eloop.max_sock;

	if (table == NULL)
		return -1;

	if (new_max_sock >= eloop.epoll_max_fd){
		next = eloop.epoll_max_fd==0?16:eloop.epoll_max_fd*2;
		temp_table = os_realloc_array(eloop.epoll_table, next,sizeof(struct eloop_sock));
		if (temp_table == NULL)
			return -1;

		eloop.epoll_max_fd = next;
		eloop.epoll_table = temp_table;
	}
	
	if (eloop.count + 1 > eloop.epoll_max_event_num) {
		next = eloop.epoll_max_event_num == 0 ? 8 :eloop.epoll_max_event_num * 2;
		temp_events = os_realloc_array(eloop.epoll_events, next,sizeof(struct epoll_event));
		if (temp_events == NULL) {
			print_debug_log("%s: malloc for epoll failed. ""%s\n", __FUNCTION__, strerror(errno));
			return -1;
		}

		eloop.epoll_max_event_num = next;
		eloop.epoll_events = temp_events;
	}
	
	tmp = os_realloc_array(table->table, table->count + 1,sizeof(struct eloop_sock));
	if (tmp == NULL) {
		return -1;
	}

	tmp[table->count].sock = sock;
	tmp[table->count].eloop_data = eloop_data;
	tmp[table->count].user_data = user_data;
	tmp[table->count].handler = handler;

	table->count++;
	table->table = tmp;
	eloop.max_sock = new_max_sock;
	eloop.count++;

	memset(&ev, 0, sizeof(ev));
	switch (table->type) {
	case EVENT_TYPE_READ:
		ev.events = EPOLLIN;
		break;
	case EVENT_TYPE_WRITE:
		ev.events = EPOLLOUT;
		break;
	/*
	 * Exceptions are always checked when using epoll, but I suppose it's
	 * possible that someone registered a socket *only* for exception
	 * handling.
	 */
	case EVENT_TYPE_EXCEPTION:
		ev.events = EPOLLERR | EPOLLHUP;
		break;
	}
	ev.data.fd = sock;
	if (epoll_ctl(eloop.epoll_fd, EPOLL_CTL_ADD, sock, &ev) < 0) {
		print_debug_log( "%s: epoll_ctl(ADD) for fd=%d ""failed. %s\n", __FUNCTION__, sock, strerror(errno));
		return -1;
	}
	memcpy(&eloop.epoll_table[sock], &table->table[table->count - 1],
		  sizeof(struct eloop_sock));

	return 1;
}

static void eloop_sock_table_remove_sock(struct eloop_sock_table *table,
                                         int sock)
{
	int i;

	if (table == NULL || table->table == NULL || table->count == 0){
		return;
	}

	for (i = 0; i < table->count; i++) {
		if (table->table[i].sock == sock){
			break;
		}
	}
	if (i == table->count){
		return;
	}

	if (i != table->count - 1) {
		memmove(&table->table[i], &table->table[i + 1],(table->count - i - 1) *sizeof(struct eloop_sock));
	}

	table->count--;
	eloop.count--;

	if (epoll_ctl(eloop.epoll_fd, EPOLL_CTL_DEL, sock, NULL) < 0) {
		print_debug_log("%s: epoll_ctl(DEL) for fd=%d ""failed. %s\n", __FUNCTION__, sock, strerror(errno));
		return;
	}
	memset(&eloop.epoll_table[sock], 0, sizeof(struct eloop_sock));
}

static struct eloop_sock_table *eloop_get_sock_table(eloop_event_type type)
{
	switch (type) {
	case EVENT_TYPE_READ:
		return &eloop.readers;
	case EVENT_TYPE_WRITE:
		return &eloop.writers;
	case EVENT_TYPE_EXCEPTION:
		return &eloop.exceptions;
	}

	return NULL;
}

int epoll_register_sock(int sock,eloop_event_type type,eloop_sock_handler handler,void *eloop_data,void *user_data)
{
	struct eloop_sock_table *table;
	
	assert(sock >=0);
	table = eloop_get_sock_table(type);
	
	return eloop_sock_table_add_sock(table,sock,handler,eloop_data,user_data);

}

void eloop_unregister_sock(int sock, eloop_event_type type)
{
	struct eloop_sock_table *table;

	table = eloop_get_sock_table(type);
	eloop_sock_table_remove_sock(table, sock);
}

int eloop_register_timeout(unsigned int secs, unsigned int usecs,eloop_timeout_handler handler,void *eloop_data, void *user_data)
{
	struct eloop_timeout *timeout ,*tmp;
	os_time_t now_sec;

	timeout = os_zalloc(sizeof(*timeout));
	if(timeout == NULL){
		return -1;
	}

	if(os_get_reltime(&timeout->time) <0){
		os_free(timeout);
		return -1;
	}

	now_sec = timeout->time.sec;
	timeout->time.sec += secs;

	if( timeout->time.sec <now_sec ){
		debug(LOG_ERR, "%s %d Too long timeout (secs=%u) to ever happen - ignore it !\n",__FUNCTION__,__LINE__,secs);
		os_free(timeout);
		return 0;
	}
	timeout->time.usec += usecs;

	while(timeout->time.usec >1000000){
		timeout->time.sec++;
		timeout->time.usec -= 1000000;
	}

	timeout->eloop_data = eloop_data;
	timeout->user_data = user_data;
	timeout->handler = handler;

	dl_list_for_each(tmp,&eloop.timeout,struct eloop_timeout,list){
		if(os_reltime_before(&timeout->time,&tmp->time)){
			dl_list_add(tmp->list.prev,&timeout->list);
			return 0;
		}
	}

	dl_list_add_tail(&eloop.timeout,&timeout->list);

	return 0;
}

int eloop_cancel_timeout(struct eloop_timeout *timeout)
{
	dl_list_del(&timeout->list);
	os_free(timeout);
}

int eloop_cancel_timeout(eloop_timeout_handler handler,void *eloop_data, void *user_data)
{
	dl_list_del(&timeout->list);
	os_free(timeout);
}

static void eloop_sock_table_dispatch(struct epoll_event *events, int nfds)
{
	struct eloop_sock *table;
	int i;

	for (i = 0; i < nfds; i++) {
		table = &eloop.epoll_table[events[i].data.fd];
		if (table->handler == NULL)
			continue;

		print_debug_log("%s %d sock %d i %d nfds %d\n",__FUNCTION__,__LINE__,table->sock,i,nfds);
		table->handler(table->sock, table->eloop_data,
			       table->user_data);
	}
}

int epoll_run()
{
	struct os_reltime tv, now;
	int timeout_ms = -1;
	/* The event loop */
	while(1){
		int n;
		struct eloop_timeout *timeout;
		
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,list);
		if (timeout) {
			os_get_reltime(&now);
			if (os_reltime_before(&now, &timeout->time)){
				os_reltime_sub(&timeout->time, &now, &tv);
			}else{
				tv.sec = tv.usec = 0;
			}

			timeout_ms = tv.sec * 1000 + tv.usec / 1000;
		}


		n= epoll_wait(eloop.epoll_fd, eloop.epoll_events,eloop.count,timeout_ms);
		
		if (n < 0 && errno !=EINTR && errno !=0){
			print_debug_log("eloop:epoll:%s\n",strerror(errno));
			break;
		}

		/* check if some registered timeouts have occurred */
		timeout = dl_list_first(&eloop.timeout, struct eloop_timeout,list);
		if (timeout) {
			os_get_reltime(&now);
			if (!os_reltime_before(&now, &timeout->time)) {
				void *eloop_data = timeout->eloop_data;
				void *user_data = timeout->user_data;
				eloop_timeout_handler handler =timeout->handler;
				eloop_remove_timeout(timeout);
				handler(eloop_data, user_data);
			}

		}

		if (n <= 0){
			continue;
		}

		eloop_sock_table_dispatch(eloop.epoll_events, n);
		
	}
	return -1;
}

