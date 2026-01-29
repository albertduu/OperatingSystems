#include "thread-worker.h"
#include <stdlib.h>

queue *init_queue() {
    queue *q = malloc(sizeof(queue));
    q->head = NULL;
    q->size = 0;
    return q;
}

void free_queue(queue *q) {
    if (!q) return;
    node *curr = q->head;
    while (curr) {
        node *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    free(q);
}

int is_empty(queue *q) {
    return (q == NULL || q->head == NULL);
}

void enqueue(queue *q, tcb *t, char *file, int line) {
    node *n = malloc(sizeof(node));
    n->thread = t;
    n->next = NULL;
    if (!q->head) q->head = n;
    else {
        node *curr = q->head;
        while (curr->next) curr = curr->next;
        curr->next = n;
    }
    q->size++;
}

tcb *dequeue(queue *q) {
    if (!q || !q->head) return NULL;
    node *n = q->head;
    tcb *t = n->thread;
    q->head = n->next;
    free(n);
    q->size--;
    return t;
}

int queue_size(queue *q) {
    int count = 0;
    node *curr = q->head;
    while (curr) {
        count++;
        curr = curr->next;
    }
    return count;
}

void enqueue_prio(queue **run_queue, tcb *t, char *file, int line) {
    enqueue(run_queue[t->priority], t, file, line);
}

tcb *get_prio_thread(queue **run_queue) {
    for (int i = NUMPRIO - 1; i >= 0; i--) {
        if (!is_empty(run_queue[i])) {
            return dequeue(run_queue[i]);
        }
    }
    return NULL;
}

tcb *evict_min_elapsed_time(queue *q) {
    if (!q || !q->head) return NULL;
    node *curr = q->head, *prev = NULL, *min_prev = NULL;
    node *min_node = curr;
    long min_time = curr->thread->elapsed_time;

    while (curr) {
        if (curr->thread->elapsed_time < min_time) {
            min_time = curr->thread->elapsed_time;
            min_prev = prev;
            min_node = curr;
        }
        prev = curr;
        curr = curr->next;
    }

    if (min_prev)
        min_prev->next = min_node->next;
    else
        q->head = min_node->next;

    tcb *t = min_node->thread;
    free(min_node);
    q->size--;
    return t;
}

void reset_prio(queue **run_queue) {
    for (int i = 0; i < NUMPRIO; i++) {
        node *curr = run_queue[i]->head;
        while (curr) {
            curr->thread->priority = NUMPRIO - 1;
            curr = curr->next;
        }
    }
}

tcb *find(queue *q, worker_t tid) {
    node *curr = q->head;
    while (curr) {
        if (curr->thread->id == tid) return curr->thread;
        curr = curr->next;
    }
    return NULL;
}

tcb *find_all(queue **run_queue, worker_t tid) {
    for (int i = 0; i < NUMPRIO; i++) {
        tcb *res = find(run_queue[i], tid);
        if (res) return res;
    }
    return NULL;
}
