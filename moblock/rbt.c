/*
 * rbt.c Red-Black Trees implementation
 *
 * Author: Thomas Niemann <thomasn at epaperpress.com>
 * Modified by: Morpheus <ebutera at users.berlios.de>
 *
 * Original code by Thomas and my changes are public domain.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

#define RBT_VERSION 0.2

/* implementation dependend declarations */
typedef enum {
    STATUS_OK,
    STATUS_MEM_EXHAUSTED,
    STATUS_DUPLICATE_KEY,
    STATUS_KEY_NOT_FOUND
} statusEnum;

typedef unsigned long keyType;            /* type of key */

/* user data stored in tree */
typedef struct {
    char blockname[50];                  /* optional related data */
    unsigned long ipmax;
    int hits;
} recType;

#define compLT(a,b) (a < b)
#define compEQ(a,b) (a == b)
#define compEQ2(a,b,c) ( (a > (b-1)) && (a < (c+1)) )	// is ip in range?
 

/* implementation independent declarations */
/* Red-Black tree description */
typedef enum { BLACK, RED } nodeColor;

typedef struct nodeTag {
    struct nodeTag *left;       /* left child */
    struct nodeTag *right;      /* right child */
    struct nodeTag *parent;     /* parent */
    nodeColor color;            /* node color (BLACK, RED) */
    keyType key;                /* key used for searching */
    recType rec;                /* user data */
} nodeType;


// stats linked list
typedef struct ll_elem {
    nodeType *rbt_node;
    struct ll_elem *next;
} ll_node;

static ll_node *ll_top=NULL;
static ll_node *ll_last=NULL;

short int ll_insert(nodeType *nt)
{
    ll_node *current;
        
    if ( ll_top == NULL ) {
        ll_top=(ll_node *)malloc(sizeof(ll_node));
        ll_top->rbt_node=nt;
        ll_top->next=NULL;
        ll_last=ll_top;
        return(0);
    } else {
          current=ll_top;
          while ( current != NULL )
              if ( current->rbt_node->key == nt->key )  // range already in stats
                  return(1);
              else current=current->next;
              
          // range not in stats, insert it
          ll_last->next=(ll_node *)malloc(sizeof(ll_node));
          ll_last->next->rbt_node=nt;
          ll_last->next->next=NULL;
          ll_last=ll_last->next;
      }
      return(0);
}

void ll_show()
{
    ll_node *current=ll_top;

    while( current != NULL ) {
        fprintf(stdout,"%s - %d hits\n",current->rbt_node->rec.blockname,
          current->rbt_node->rec.hits);
        current=current->next;
    }
}

void ll_log()
{
    ll_node *current=ll_top;
    FILE *fp;
    time_t tp;
    
    fp=fopen("/var/log/MoBlock.log","a");
    if ( fp == NULL ) {
        fprintf(stderr,"Error opening stats file /var/log/MoBlock.log\n");
        perror("ll_log");
        return;
    }
    tp=time(NULL);
    fprintf(fp,"%s MoBlock Stats\n\n",ctime(&tp));
                
    while( current != NULL ) {
        fprintf(fp,"   %s - %d hits\n",current->rbt_node->rec.blockname,
                                       current->rbt_node->rec.hits);
        current=current->next;
    }
    fprintf(fp,"----------------------------------------\n");
    if ( fclose(fp) != 0 ) {
        perror("Error closing stats file /var/log/MoBlock.log");
        return;
    }
}

#define NIL &sentinel           /* all leafs are sentinels */
static nodeType sentinel = { NIL, NIL, 0, BLACK, 0};

/* last node found, optimizes find/delete operations */
static nodeType *lastFind;

static nodeType *root = NIL;    /* root of Red-Black tree */

static void rotateLeft(nodeType *x) {

   /**************************
    *  rotate node x to left *
    **************************/

    nodeType *y = x->right;

    /* establish x->right link */
    x->right = y->left;
    if (y->left != NIL) y->left->parent = x;

    /* establish y->parent link */
    if (y != NIL) y->parent = x->parent;
    if (x->parent) {
        if (x == x->parent->left)
            x->parent->left = y;
        else
            x->parent->right = y;
    } else {
        root = y;
    }

    /* link x and y */
    y->left = x;
    if (x != NIL) x->parent = y;
}

static void rotateRight(nodeType *x) {

   /****************************
    *  rotate node x to right  *
    ****************************/

    nodeType *y = x->left;

    /* establish x->left link */
    x->left = y->right;
    if (y->right != NIL) y->right->parent = x;

    /* establish y->parent link */
    if (y != NIL) y->parent = x->parent;
    if (x->parent) {
        if (x == x->parent->right)
            x->parent->right = y;
        else
            x->parent->left = y;
    } else {
        root = y;
    }

    /* link x and y */
    y->right = x;
    if (x != NIL) x->parent = y;
}

static void insertFixup(nodeType *x) {

   /*************************************
    *  maintain Red-Black tree balance  *
    *  after inserting node x           *
    *************************************/

    /* check Red-Black properties */
    while (x != root && x->parent->color == RED) {
        /* we have a violation */
        if (x->parent == x->parent->parent->left) {
            nodeType *y = x->parent->parent->right;
            if (y->color == RED) {

                /* uncle is RED */
                x->parent->color = BLACK;
                y->color = BLACK;
                x->parent->parent->color = RED;
                x = x->parent->parent;
            } else {

                /* uncle is BLACK */
                if (x == x->parent->right) {
                    /* make x a left child */
                    x = x->parent;
                    rotateLeft(x);
                }

                /* recolor and rotate */
                x->parent->color = BLACK;
                x->parent->parent->color = RED;
                rotateRight(x->parent->parent);
            }
        } else {

            /* mirror image of above code */
            nodeType *y = x->parent->parent->left;
            if (y->color == RED) {

                /* uncle is RED */
                x->parent->color = BLACK;
                y->color = BLACK;
                x->parent->parent->color = RED;
                x = x->parent->parent;
            } else {

                /* uncle is BLACK */
                if (x == x->parent->left) {
                    x = x->parent;
                    rotateRight(x);
                }
                x->parent->color = BLACK;
                x->parent->parent->color = RED;
                rotateLeft(x->parent->parent);
            }
        }
    }
    root->color = BLACK;
}

statusEnum insert(keyType key, recType *rec) {
    nodeType *current, *parent, *x;

   /***********************************************
    *  allocate node for data and insert in tree  *
    ***********************************************/

    /* find future parent */
    current = root;
    parent = 0;
    while (current != NIL) {
        if (compEQ(key, current->key)) 
            return STATUS_DUPLICATE_KEY;
        parent = current;
        current = compLT(key, current->key) ?
            current->left : current->right;
    }

    /* setup new node */
    if ((x = malloc(sizeof(nodeType))) == NULL)
        return STATUS_MEM_EXHAUSTED;
    x->parent = parent;
    x->left = NIL;
    x->right = NIL;
    x->color = RED;
    x->key = key;
    x->rec = *rec;

    /* insert node in tree */
    if(parent) {
        if(compLT(key, parent->key))
            parent->left = x;
        else
            parent->right = x;
    } else {
        root = x;
    }

    insertFixup(x);
    lastFind = NULL;

    return STATUS_OK;
}

static void deleteFixup(nodeType *x) {

   /*************************************
    *  maintain Red-Black tree balance  *
    *  after deleting node x            *
    *************************************/

    while (x != root && x->color == BLACK) {
        if (x == x->parent->left) {
            nodeType *w = x->parent->right;
            if (w->color == RED) {
                w->color = BLACK;
                x->parent->color = RED;
                rotateLeft (x->parent);
                w = x->parent->right;
            }
            if (w->left->color == BLACK && w->right->color == BLACK) {
                w->color = RED;
                x = x->parent;
            } else {
                if (w->right->color == BLACK) {
                    w->left->color = BLACK;
                    w->color = RED;
                    rotateRight (w);
                    w = x->parent->right;
                }
                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->right->color = BLACK;
                rotateLeft (x->parent);
                x = root;
            }
        } else {
            nodeType *w = x->parent->left;
            if (w->color == RED) {
                w->color = BLACK;
                x->parent->color = RED;
                rotateRight (x->parent);
                w = x->parent->left;
            }
            if (w->right->color == BLACK && w->left->color == BLACK) {
                w->color = RED;
                x = x->parent;
            } else {
                if (w->left->color == BLACK) {
                    w->right->color = BLACK;
                    w->color = RED;
                    rotateLeft (w);
                    w = x->parent->left;
                }
                w->color = x->parent->color;
                x->parent->color = BLACK;
                w->left->color = BLACK;
                rotateRight (x->parent);
                x = root;
            }
        }
    }
    x->color = BLACK;
}

statusEnum delete(keyType key) {
    nodeType *x, *y, *z;

   /*****************************
    *  delete node z from tree  *
    *****************************/

    /* find node in tree */
    if (lastFind && compEQ(lastFind->key, key))
        /* if we just found node, use pointer */
        z = lastFind;
    else {
        z = root;
        while(z != NIL) {
            if(compEQ(key, z->key)) 
                break;
            else
                z = compLT(key, z->key) ? z->left : z->right;
        }
        if (z == NIL) return STATUS_KEY_NOT_FOUND;
    }

    if (z->left == NIL || z->right == NIL) {
        /* y has a NIL node as a child */
        y = z;
    } else {
        /* find tree successor with a NIL node as a child */
        y = z->right;
        while (y->left != NIL) y = y->left;
    }

    /* x is y's only child */
    if (y->left != NIL)
        x = y->left;
    else
        x = y->right;

    /* remove y from the parent chain */
    x->parent = y->parent;
    if (y->parent)
        if (y == y->parent->left)
            y->parent->left = x;
        else
            y->parent->right = x;
    else
        root = x;

    if (y != z) {
        z->key = y->key;
        z->rec = y->rec;
    }


    if (y->color == BLACK)
        deleteFixup (x);

    free (y);
    lastFind = NULL;

    return STATUS_OK;
}

statusEnum find(keyType key, recType *rec) {

   /*******************************
    *  find node containing data  *
    *******************************/

    nodeType *current = root;
    while(current != NIL) {
        if(compEQ2(key, current->key,current->rec.ipmax)) {
            ll_insert(current);
            (current->rec.hits)++;
            *rec = current->rec;
            lastFind = current;
            return STATUS_OK;
        } else {
            current = compLT (key, current->key) ?
                current->left : current->right;
        }
    }
    return STATUS_KEY_NOT_FOUND;
}
