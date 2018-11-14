# call from command line, for example:
# python vol.py -f /media/sf_Shared/KALI/"MSEdge - Win10_preview-eaaa27c2-dll_inj_after.vmem" --profile="Win10x64_14393" volshell
# inside volshell enviromnent -->  execfile('FindDllInj.py')

#---- Set Parameters (TimeWindow, OneProcess, WhiteList) ----
TimeWindow=10
OneProcess=False
WhiteList=[]
#TODO fill whitelist with dll names

# Create output file
Out_SuspectedDll = open('SuspectedDlls.txt','w')
import datetime 
# introduction line 
Out_SuspectedDll.write(str(datetime.datetime.now()) + '\t' + "FindDllInj on "+ sys.argv[2]+ " TimeWindow: " +str(TimeWindow ) + " OneProcess: " + str(OneProcess)+ '\n')
# writing headers
Out_SuspectedDll.write("Pid" + '\t' + "Description" + '\t' + "ImageFileName" + '\t' + "Dll" + '\t' +"DllLoadTime" + '\t' + "TimeDifference from previously loaded Dll in sec" + '\t' + "ThreadPid" + '\t' + "ThreadTid" + '\t' + "ThreadLoadTime" + '\t' + "ThreadExitTime" + '\t'+ "ThreadHandlePid" +'\n')

from datetime import datetime
import time
import calendar

# initialize lists
AllProcessHandle_List=[]
AllProcessSuspectedDlls=[]
CsrssPids=[]
#---- Get all Processes from memory Image ----
for proc_id in getprocs():
	#---- Read Processes space ---- 
	p_id= proc_id.UniqueProcessId     
	cc(pid=p_id)
	process=proc()
	process_space = process.get_process_address_space()

	if str(process.ImageFileName).lower()=="csrss.exe":
		CsrssPids.append(p_id)

	# ---- Examine Processes VADs: find VADs with specific characteristics and get the corresponding DLL Names ----
	DLLsMappedOnce=[]
	for vad in process.VadRoot.traverse():
	     data = process_space.read(vad.Start, 1024)
	     if data:
		 found = data.find("MZ")
		 if found != -1:             
			if hasattr(vad,"ControlArea"):         
	
				if OneProcess == True:
					if int(vad.ControlArea.NumberOfMappedViews) == 1 and \
					   int(vad.ControlArea.NumberOfUserReferences)==1 :
						DLLsMappedOnce.append(str(vad.FileObject.FileName))
				else:
					DLLsMappedOnce.append(str(vad.FileObject.FileName))

	
	#---- Scan Process PE for IAT entries ---- 

	#"Scan" PE to reproduce the IAT table - 1st method 
	DLLsFromImport=[]
	dos_header = obj.Object("_IMAGE_DOS_HEADER",offset = process.Peb.ImageBaseAddress,vm = process_space)
	nt_header = dos_header.get_nt_header()
	data_dir = nt_header.OptionalHeader.DataDirectory[1]

	i = 0

	# The following is taken from plugins/overlays/windows/pe_vtypes.py, imports() function of class _LDR_DATA_TABLE_ENTRY
	# TODO --> desc_size = self.obj_vm.profile.get_obj_size('_IMAGE_IMPORT_DESCRIPTOR')
	desc_size=20
	while 1:
		    desc = obj.Object('_IMAGE_IMPORT_DESCRIPTOR',
			      vm = process_space,
			      offset = process.Peb.ImageBaseAddress + data_dir.VirtualAddress + (i * desc_size),
			      parent = self)

		    # Stop if the IID is paged or all zeros
		    if desc == None or desc.is_list_end():
			break

		    # Stop if the IID contains invalid fields 
		    if not desc.valid(nt_header):
			break

		    DllName=obj.Object("String",offset = desc.Name+process.Peb.ImageBaseAddress,vm = process_space, length = 128)
		    DLLsFromImport.append(str(DllName).lower())   

		    i += 1

	if len(DLLsFromImport) == 0:
		Out_SuspectedDll.write(str(p_id) + '\t' + "Warning: No Imported Dll found" + '\t' + process.ImageFileName +'\n')


	#---- Get Process Loaded Dlls ----
	DllsLoaded=[]
	mods = list(process.get_load_modules())
	if len(mods)>0:
		# mods[0] represents the exe module
		previous_load=mods[0].LoadTime
		#---- Get Loaded Dlls Information ----
		for mod in mods:
			# DllsLoaded layout 
			# mod.LoadTime-previous_load : time difference between current and previous loaded module (in seconds)
			DllsLoaded.append([str(mod.FullDllName).lower(),process.ImageFileName, p_id, mod.LoadCount, mod.ObsoleteLoadCount, mod.ReferenceCount, hex(mod.DllBase), hex(mod.ParentDllBase), mod.ImageDll,  mod.LoadTime, mod.LoadReason,mod.BaseDllName, mod.LoadTime-previous_load])
			previous_load=mod.LoadTime

	if len(DllsLoaded) == 0:

		Out_SuspectedDll.write(str(p_id) + '\t' + "Warning: No Loaded Dlls found" + '\t' + process.ImageFileName +'\n')

	SuspectedDlls=[]

	#---- Characterize DLL : Find suspicious loaded DLLs in process ----
	for dll in DllsLoaded:
		
		#  DllName-->  dll name
		t1=dll[0].rfind(".dll")
		t2=dll[0].rfind("\\")
		DllName =dll[0][t2+1:t1+4]
		found1=False
		for item in DLLsFromImport:
			if item.lower().find(DllName)!=-1:
				found1=True
				break
		found2=False
		for item in DLLsMappedOnce:
			if item.lower().find(DllName)!=-1:
				found2=True
				break

		#---- The DLL does not exist in process IAT AND the corresponding VAD fulfill OneProcess criteria ----
		if found1==False and found2==True:
			# ---- DLL loaded at least 1 sec after from previously loaded DLL AND ---- 
			# ---- LoadReason==LoadReasonDynamicLoad OR ObsoleteLoadCount is 6 (DLL explicitly loaded using LoadLibrary function) ----
			if dll[12] > 1 and  (dll[10]==4 or dll[4]==6): 
				#---- Is the DLL in the White List? ----
				if dll[0] not in WhiteList:
					# append ImageFileName, p_id, mod.FullDllName, mod.LoadTime, mod.LoadTime-previous_load , mod.DllBase, mod.LoadTime in UTC
					SuspectedDlls.append([str(process.ImageFileName),int(dll[2]),dll[0], int(dll[9]),int(dll[12]),dll[6], datetime.utcfromtimestamp(dll[9])])
				else:
					Out_SuspectedDll.write(str(p_id) + '\t' + "Warning: Dll in WhiteList" + '\t' + dll[0] +'\n')	
		

	if len(SuspectedDlls) >0:
	
		#---- Get Threads in the context of the process (in Thread List) ----
		Thread_List=[]
		for thread in process.ThreadListHead.list_of_type("_ETHREAD", "ThreadListEntry"):
			timestamp_utc = calendar.timegm(time.strptime(str(thread.CreateTime), "%Y-%m-%d %H:%M:%S UTC+0000"))
			Thread_List.append([int(thread.Cid.UniqueProcess), int(thread.Cid.UniqueThread), str(thread.CreateTime), timestamp_utc, str(thread.ExitTime or ' '), hex(thread.StartAddress)])
	
	#---- Get Process Handles (in Handle_List) and update ALL Processes' handles (AllProcessHandle_List) ----
	Handle_List=[]
	process.ObjectTable.HandleTableList
	
	pid=int(p_id)
	for handle in process.ObjectTable.handles():
		if not handle.is_valid():
			continue
		
		object_type = handle.get_object_type()

		if object_type == "Thread":
			thrd_obj = handle.dereference_as("_ETHREAD")
			# Details handle PID, TID, process id that owns the handle
			Handle_List.append([int(thrd_obj.Cid.UniqueProcess),int(thrd_obj.Cid.UniqueThread),p_id])
			AllProcessHandle_List.append([int(thrd_obj.Cid.UniqueProcess),int(thrd_obj.Cid.UniqueThread),p_id])

	handle_pid=0 # to be filled later
	len_SuspectedDlls=len(SuspectedDlls) 
	for i in range(0,len_SuspectedDlls):
	
		for thread_item in Thread_List:
			#---- Is there a thread created in DLLs TimeWindow? AND still executing? ----
			# ( if thread creation time between SupsectedDllLoadTime and SupsectedDllLoadTime + TimeWindow 
			#   and thread not terminated ) 
			if (SuspectedDlls[i][3] >= thread_item[3] and SuspectedDlls[i][3] <= thread_item[3] + TimeWindow) \
				and thread_item[4] ==" ": 
						
				FoundInHandleList=False
				for hanle_item in Handle_List:
					# TID of thread same as TID of specific process handle (meaning the thread is created by the specific process)  --> not suspicious
					if thread_item[1] == hanle_item[1]  : 
						FoundInHandleList =True						
					
				#---- If this thread  is not handled/created by the specific process --> suspicious ----
				if FoundInHandleList == False: 					
					AllProcessSuspectedDlls.append([SuspectedDlls[i], thread_item, handle_pid])
 
# Minimize False Positives
len_AllProcessSuspectedDlls=len(AllProcessSuspectedDlls) 
for i in range(0,len_AllProcessSuspectedDlls):
	
	FoundInHandleList=False
	FoundInCrss=False
	
	for handle_item in AllProcessHandle_List:
		# TID found in another processes' handle --> suscicious
		if AllProcessSuspectedDlls[i][1][1] == handle_item[1] :
			FoundInHandleList=True
			
			#---- The thread is not handled by csrss.exe --> suspicious
			# Handle on the Thread Id not created by csrss.exe  --> suscicious
			if handle_item[2] not in CsrssPids: 
				AllProcessSuspectedDlls[i][2]=int(handle_item[2]) #--> update with the malware Pid 

				Out_SuspectedDll.write(str(AllProcessSuspectedDlls[i][0][1]) + '\t' + "Suspicious process" + '\t' + str(AllProcessSuspectedDlls[i][0][0]) + '\t' + str(AllProcessSuspectedDlls[i][0][2]) + '\t' + str(AllProcessSuspectedDlls[i][0][6]) + '\t' + str(AllProcessSuspectedDlls[i][0][4]) + '\t' + str(AllProcessSuspectedDlls[i][1][0]) + '\t' + str(AllProcessSuspectedDlls[i][1][1]) + '\t' + str(AllProcessSuspectedDlls[i][1][2]) + '\t' + str(AllProcessSuspectedDlls[i][1][4]) + '\t'+ str(AllProcessSuspectedDlls[i][2]) +'\n')
			else:
				FoundInCrss=True

	if FoundInHandleList==False:
		Out_SuspectedDll.write(str(AllProcessSuspectedDlls[i][0][1]) + '\t' + "Warning: No handle found" + '\t' + str(AllProcessSuspectedDlls[i][0][0]) + '\t' + str(AllProcessSuspectedDlls[i][0][2]) + 
'\t' + str(AllProcessSuspectedDlls[i][0][6]) + '\t' + str(AllProcessSuspectedDlls[i][0][4]) + '\t' + str(AllProcessSuspectedDlls[i][1][0]) + '\t' + str(AllProcessSuspectedDlls[i][1][1]) + '\t' + str(AllProcessSuspectedDlls[i][1][2]) + '\t' +  str(AllProcessSuspectedDlls[i][1][4]) + '\t' +str(AllProcessSuspectedDlls[i][2]) +'\n')

# footer line 
import datetime 
Out_SuspectedDll.write(str(datetime.datetime.now()) + '\n')
Out_SuspectedDll.close()



