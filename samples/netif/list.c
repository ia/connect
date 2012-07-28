
/* basics: http://www.cprogramming.com/tutorial/c/lesson15.html */

#include <stdio.h>
#include <stdlib.h>

struct list {
	int data;
	struct list *next;
};

int list_enum(struct list *l)
{
	while (l) {
		printf("list->data: %d\n", l->data);
		l = l->next;
	}
}

int list_add(struct list *l, struct list *n)
{
	while (l) {
		if (!l->next) {
			l->next = n;
			break;
		} else {
			l = l->next;
		}
	}
}

int list_m_add(struct list *l, int data)
{
	struct list *t;
	t = malloc(sizeof(struct list));
	t->next = NULL;
	t->data = data;
	
	while (l) {
		if (!l->next) {
			l->next = t;
			break;
		} else {
			l = l->next;
		}
	}
}

int list_remove(struct list *l, int data)
{
	while (l) {
		if (l->next->data == data) {
			if(!l->next->next) {
				l->next = NULL;
			} else {
				l->next = l->next->next;
			}
			break;
		}
		l = l->next;
	}
}

int main(int argc, const char *argv[])
{
	struct list *l;
	l = malloc(sizeof(struct list));
	l->next = NULL;
	l->data = 1;
	
	struct list *l2;
	l2 = malloc(sizeof(struct list));
	l2->next = NULL;
	l2->data = 10;
	
	l->next = l2;
	
	list_enum(l);
	
	struct list *l3;
	l3 = malloc(sizeof(struct list));
	l3->data = 20;
	
	list_add(l, l3);
	
	list_enum(l);
	
	list_remove(l, 10);
	
	list_enum(l);
	
	list_m_add(l, 100);
	
	list_enum(l);
	
	return 0;
}

