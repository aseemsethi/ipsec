#include "stdio.h"
#include "stdlib.h"

// IKE STATES
#define NO_CHANGE 4
#define IKE_START_STATE 0
#define IKE_INIT_STATE 1
#define IKE_AUTH_STATE 2
#define IKE_ESTAB_STATE 3

#define INIT_EVENT 0
#define TIMEOUT_EVENT 1
#define DATA_EVENT 2
#define REDIRECT_EVENT 3

#define FSM_Q_SIZE 1000

typedef struct {
	int ikeEvent;
	void *ike;
	unsigned char *fsmBuff;
} fsmParam;

fsmParam *ikeFsmQ[FSM_Q_SIZE];

typedef struct {
	int nextState;
} ikeStruct;

// FSM
typedef struct {
	int (*funcPtr)(ikeStruct *ike, int ikeEvent, unsigned char* fsmBuff);
	int nextState;
} fsmStruct;

int InvalidEvent (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
	if (buff != NULL)
		free(buff);
	return 1;
}
int timeoutEvent (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
	if (buff != NULL)
		free(buff);
	return 1;
}
int dataEvent (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
	if (buff != NULL)
		free(buff);
	return 1;
}
int ikeStart (ikeStruct *ike, int ikeEvent, unsigned char *buff) {
	if (buff != NULL)
		free(buff);
	return 1;
};

static fsmStruct ikeFsm[4][4] = {
	{ /* IKE_START */
		{ikeStart, IKE_INIT_STATE}, //INIT_EVENT
		{InvalidEvent, NO_CHANGE},  //TIMEOUT_EVENT
		{InvalidEvent, NO_CHANGE},  //DATA_EVENT
		{InvalidEvent, NO_CHANGE}   //REDIRECT_EVENT
	},
	{ /* IKE_INIT */
		{InvalidEvent, NO_CHANGE},
		{timeoutEvent, NO_CHANGE},
		{dataEvent, IKE_AUTH_STATE},
		{InvalidEvent, NO_CHANGE}
	},
	{ /* IKE_AUTH */
		{InvalidEvent, NO_CHANGE},
		{InvalidEvent, NO_CHANGE},
		{dataEvent, IKE_ESTAB_STATE},
		{ikeStart, IKE_INIT_STATE}
	},
	{ /* IKE_ESTAB */
		{InvalidEvent, NO_CHANGE},
		{InvalidEvent, NO_CHANGE},
		{dataEvent, NO_CHANGE},
		{InvalidEvent, NO_CHANGE}
	}
};

main() {
	printf("\n IPSec sim started..");
	return 1;
}
