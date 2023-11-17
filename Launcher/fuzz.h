#pragma once

#define MAX_CHILD 20
#define MAX_PIDS 100

int AddMutationToList(Recording* rec, MutationType* mutType, MutationValue* mutVal);
BOOL MutationExists(Recording* rec);
Mutation* GetCurrentMutation();

struct RecordList {
	Recording rec;
	RecordList* next;
};

// per-instance recording (1 per connecting process)
struct LocalRecording {
	// NOTE: this list grows backwards, the last call is the head.
	RecordList* recHead = NULL;
	RecordList* recCurr = NULL;
};

struct Origins {
	UINT64 origin;
	Origins* next;
};

// one execution instance
struct Execution {
	LocalRecording recordings[MAX_CHILD];
	volatile LONG RecIndex;
	
	// stack trace origin + unique counts
	LONG CallCounts[CALL_END];
	Origins* CallOrigins[CALL_END];

	// pointer to last previous mutation
	Mutation* mutStore;
	// doubly linked list
	Execution* prev;
	Execution* next;
};


struct Frame {
	Execution* firstExec = NULL;
	Execution* currExec = NULL;
	Mutation* mutHead = NULL;
	Mutation* mutCurr = NULL;
	DWORD dwMutationCount = 0;

	// list of mutations to avoid due to backtracking
	Mutation* skip = NULL;

	// callcount sum (avoid recalc)
	LONG act;
};

struct BackTrackInfo {
	DWORD BackTrackAttempts;
	DWORD BackTrackKept;
	LONG InitAct;
};