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
int ikeFsmQHead = 0;
int ikeFsmQTail = 0;

typedef struct {
	int     curState;
} ikeStruct;

char* eventToString(int event) {
    switch(event) {
    case 0: return "INIT_EVENT";
    case 1: return "TIMEOUT_EVENT";
    case 2: return "DATA_EVENT";
    default: return "UNKNOWN EVENT";
    }
}
char* stateToString(int state) {
    switch(state) {
    case 0: return "IKE_START_STATE";
    case 1: return "IKE_INIT_STATE";
    case 2: return "IKE_AUTH_STATE";
    case 3: return "IKE_ESTAB_STATE";
    default: return "UNKNOWN STATE";
    }
}


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

fsmRoutine() {
        ikeStruct *ike;
        fsmParam *fp;
        unsigned char *fsmBuff;
        int event;
        int count = 0;

        printf("\n.................................IKE FSM starting ");
        while (1) {
        // "do" is done here, since when Q is full, QHead = QTail
        do {
            if (ikeFsmQ[ikeFsmQHead] != 0) {
                    fp = ikeFsmQ[ikeFsmQHead];
                    ike = fp->ike;
                    fsmBuff = fp->fsmBuff;
                    event = fp->ikeEvent;
                    ikeFsm[ike->curState][event].funcPtr(ike, event, fsmBuff);
                    if (ikeFsm[ike->curState][event].nextState != NO_CHANGE)
                            ike->curState =
                                    ikeFsm[ike->curState][event].nextState;
                    free(ikeFsmQ[ikeFsmQHead]);
                    ikeFsmQ[ikeFsmQHead] = 0;
                    if (ikeFsmQHead == FSM_Q_SIZE-1) {
                            printf("ikeFsmQHead wraps to 0\n");
                            ikeFsmQHead = 0;
                    } else
                            ikeFsmQHead++;
                    if ((++count % 50) == 0) {
                            printf("...FSM routine sleeping\n");
                            sleep(3);
                    }
            } else {
            // stay at this same ikeFsmQHead point and 
            // keep checking every second.
                    sleep(1);
                    continue;
            }
        } while(ikeFsmQHead != ikeFsmQTail);
            sleep(1);
        }
}

ikeFsmExecute (ikeStruct *ike, int ikeEvent, unsigned char *fsmBuff)
{
    fsmParam  *fp;
    char      status;

    printf("\nIKE_FSM: Cur State: %s, Event: %s",
            stateToString(ike->curState), eventToString(ikeEvent));

    fp = (fsmParam*)malloc(sizeof(fsmParam));
    if (fp == 0) {
        printf("\n No mem at ikeFsmExecute");
        return;
    }
    fp->ikeEvent = ikeEvent;
    fp->ike = ike;
    fp->fsmBuff = fsmBuff;

    if (ikeFsmQ[ikeFsmQTail] == 0) {
        ikeFsmQ[ikeFsmQTail] = fp;
        if (ikeFsmQTail == FSM_Q_SIZE-1) {
            printf("ikeFsmQTail wraps to 0\n");
            ikeFsmQTail = 0;
        } else
            ikeFsmQTail++;
    } else {
        printf("FSM event dropped...Q full\n");
    }
}


main() {
	printf("\n IPSec sim started..");
	return 1;
}
