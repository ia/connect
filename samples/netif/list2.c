
/* basics: http://www.cprogramming.com/tutorial/c/lesson15.html */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct node {
	int   i;
	char *text;
};

struct list {
	struct node *data;
	struct list *next;
};

int list_enum(struct list *l)
{
	while (l) {
		if (l->data)
			printf("list->node->i: %d\n", l->data->i);
		if (l->data && l->data->text) {
			printf("list->node->text: %s\n", l->data->text);
		}
		l = l->next;
	}
}

int list_add(struct list *l, struct node *n)
{
	struct list *t = malloc(sizeof(struct list));
	t->data = malloc(sizeof(struct node));
	printf("%d\n", __LINE__);
	memcpy(t->data, n, sizeof(struct node));
	printf("%d\n", __LINE__);
	t->next = NULL;
	
	while (l) {
		if (!l->next) {
			l->next = t;
			break;
		} else {
			l = l->next;
		}
	}
}

int list_add_once(struct list *l, struct node *n)
{
	struct list *t = malloc(sizeof(struct list));
	t->data = malloc(sizeof(struct node));
	printf("%d\n", __LINE__);
	memcpy(t->data, n, sizeof(struct node));
	printf("%d\n", __LINE__);
	t->next = NULL;
	
	while (l) {
		if (l->data && l->data->i == t->data->i) {
			break;
		} else if (!l->next) {
			l->next = t;
			break;
		} else {
			l = l->next;
		}
	}
}

int main(int argc, const char *argv[])
{
	struct list *l;
	l = malloc(sizeof(struct list));
	l->next = NULL;
	l->data = NULL;
	
	struct node *n;
	n = malloc(sizeof(struct node));
	n->text = NULL;
	//n->i = 10;
	
	int i = 0;
	for (i = 0; i < 3; i++) {
		n->i = i+10;
		list_add_once(l, n);
	}
	
	for (i = 0; i < 3; i++) {
		n->i = i+10;
		list_add_once(l, n);
	}
	
	list_enum(l);
	
	return 0;
}

