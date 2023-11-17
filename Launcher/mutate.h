#pragma once

BOOL GenPreventiveMutationsAll();
BOOL GenerateResponsiveMutationsAll(Execution* exec);
RecordList* GenerateResponsiveVolatileMutation(Execution* exec, RecordList* start, LONG* index);
RecordList* GenerateResponsiveMutations(Execution* exec, RecordList* start);
