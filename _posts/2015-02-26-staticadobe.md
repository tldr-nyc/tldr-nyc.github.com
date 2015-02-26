---
layout: post
title: "staticadobe.py"
description: ""
category: expdev
tags: [expdev, ida]
---
{% include JB/setup %}

Decoding EScript.api JavaScript structures

### staticadobe.py

{% highlight Python %}
#import wingdbstub
#wingdbstub.Ensure()

from idaapi import *

def acroEvent(ptrAllowedEvents, counterAllowedEvents):
    
    addr = ptrAllowedEvents
    for i in range(0, counterAllowedEvents):
        #Event Type [ptr to "App"]
        ptrEventType = Dword(addr)
        EventType = GetString(ptrEventType, -1, ASCSTR_C)
        addr += 4
        
        # Event Name [ptr to "Init"]
        ptrEventName = Dword(addr)
        EventName = GetString(ptrEventName, -1, ASCSTR_C)
        addr += 4
        
        print "\t\t\tEvent: %s\%s" % (EventType, EventName)
    
    print ""
    
def acroSecPriv(ptrSecurity):

	# Security Priviledge Structure

    addr = ptrSecurity
    offset = 0
    
    # Unkown * 2 + Always Zero [0x0, 0x0, 0x0]
    # print "\t\tOffset +0x%02x ???" % offset
    addr += 12
    offset += 12
    
    # ptrPerms (document permissions, ex: Perm to Print, Save, etc.) [0x0]
    ptrPerms = Dword(addr)
    # print "\t\tOffset +0x%02x ptrPerms 0x%08x" % (offset, ptrPerms)
    addr += 4
    offset += 4
    
    # Perms counter [0x0]
    counterPerms = Dword(addr)
    # print "\t\tOffset +0x%02x counterPerms 0x%08x" % (offset, counterPerms)
    addr += 4
    offset += 4
    
    # Allowed Events [ptr to Event List]
    ptrAllowedEvents = Dword(addr)
    # print "\t\tOffset +0x%02x ptrAllowedEvents 0x%08x" % (offset, ptrAllowedEvents)
    addr += 4
    offset += 4
    
    # Allowed Events counter [0x2]
    counterAllowedEvents = Dword(addr)
    # print "\t\tOffset +0x%02x counterAllowedEvents 0x%08x\n" % (offset, counterAllowedEvents)
    addr += 4
    offset += 4
    if(counterAllowedEvents != 0x0):
        acroEvent(ptrAllowedEvents, counterAllowedEvents)

def acroMembers(ptrMembers, counterMembers):

	# [Object 0x09] Address: 0x23949df8
    # Offset +0x00 MemberName "browseForDoc"
    # Offset +0x04 ptrSecurityGetter    0x00000000
    # Offset +0x08 ptrSecuritySetter    0x00000000
    # Offset +0x0c ptrSecurityMethod    0x23949a20 <-- Security Priviledge Structure
    # Offset +0x10 ptrArgInfo           0x23947f80
    # Offset +0x14 counterArgInfo       0x00000006
    # Offset +0x18 ???                  0x00000002
    # Offset +0x1c ???                  0x00000004

    addr = ptrMembers
    for i in range(0, counterMembers):
        offset = 0
        # print "\t[Member 0x%02x] Address: 0x%08x" % (i, addr)
        
        
        # Member Name [eg. ptr to "browseForDoc"]
        ptrMemberName = Dword(addr)
        MemberName = GetString(ptrMemberName, -1, ASCSTR_C)
        print "\tMember \"%s\"" % MemberName
        addr += 4
        offset += 4
        
        # Security Privileges (Getter) [0x0]
        ptrSecurityGetter = Dword(addr)
        # print "\tOffset +0x%02x ptrSecurityGetter 0x%08x" % (offset, ptrSecurityGetter)
        addr += 4
        offset += 4
        
        # Security Privileges (Setter) [0x0]
        ptrSecuritySetter = Dword(addr)
        # print "\tOffset +0x%02x ptrSecuritySetter 0x%08x" % (offset, ptrSecuritySetter)
        addr += 4
        offset += 4
        
        # Security Privileges (Method)
        ptrSecurityMethod = Dword(addr)
        # print "\tOffset +0x%02x ptrSecurityMethod 0x%08x" % (offset, ptrSecurityMethod)
        addr += 4
        offset += 4
        
        # Arguments Information [0x0]
        ptrArgInfo = Dword(addr)
        # print "\tOffset +0x%02x ptrArgInfo 0x%08x" % (offset, ptrArgInfo)
        addr += 4
        offset += 4
        
        # ArgInfo Counter [0x0]
        counterArgInfo = Dword(addr)
        # print "\tOffset +0x%02x counterArgInfo 0x%08x" % (offset, counterArgInfo)
        addr += 4
        offset += 4
        
        # ???
        unknown1 = Dword(addr)
        # print "\tOffset +0x%02x ??? 0x%08x" % (offset, unknown1)
        addr += 4
        offset += 4
        
        # ???
        unknown2 = Dword(addr)
        # print "\tOffset +0x%02x ??? 0x%08x\n" % (offset, unknown2)
        addr += 4
        offset += 4
        
        if(ptrSecurityMethod != 0x0):
            print "\t\tSecurity Priviledged for Method, have a list of allowed Events:"
            acroSecPriv(ptrSecurityMethod)
        if(ptrSecurityGetter != 0x0):
            print "\t\tSecurity Priviledged for Getter - (property?)"
            acroSecPriv(ptrSecurityGetter)
        if(ptrSecuritySetter != 0x0):
            print "\t\tSecurity Priviledged for Setter - (property?)"
            acroSecPriv(ptrSecuritySetter)         

if __name__ == '__main__':
    
    addr = 0x23975798
    for x in range(0, 221):
        offset = 0
        
        #print "[Object %d] Address: 0x%08x" % (x, addr)
        # Object Name [ptr to "App"]
        ptrObjectName = Dword(addr)
        ObjectName = GetString(ptrObjectName, -1, ASCSTR_C)
        print "Object \"%s\"" % ObjectName
        addr += 4
        offset += 4
        
        # Unknown [0x0]
        # print "Offset +0x%02x ???" % offset
        addr += 4
        offset += 4
        
        # Members [ptr to 5C Members Structures]
        ptrMembers = Dword(addr)
        # print "Offset +0x%02x ptrMembers 0x%08x" % (offset, ptrMembers)
        addr += 4
        offset += 4
        
        # Members counter [0x5c]
        counterMembers = Dword(addr)
        # print "Offset +0x%02x counterMembers = 0x%x\n" % (offset, counterMembers)
        addr += 4
        offset += 4
        
        acroMembers(ptrMembers, counterMembers)
{% endhighlight %}

### Console

{% highlight text %}
Object "actions"
	Member "Convert"
	Member "Decalibrate"
	Member "DownConvert"
	Member "Preserve"
Object "ADBC"
	Member "Binary"
	Member "Boolean"
	Member "Date"
	Member "getDataSourceList"
	Member "newConnection"
	Member "Numeric"
	Member "SQLT_BIGINT"
	Member "SQLT_BINARY"
	Member "SQLT_BIT"
	Member "SQLT_CHAR"
	Member "SQLT_DATE"
	Member "SQLT_DECIMAL"
	Member "SQLT_DOUBLE"
	Member "SQLT_FLOAT"
	Member "SQLT_INTEGER"
	Member "SQLT_LONGVARBINARY"
	Member "SQLT_LONGVARCHAR"
	Member "SQLT_NUMERIC"
	Member "SQLT_REAL"
	Member "SQLT_SMALLINT"
	Member "SQLT_TEST"
	Member "SQLT_TIME"
	Member "SQLT_TIMESTAMP"
	Member "SQLT_TINYINT"
	Member "SQLT_VARBINARY"
	Member "SQLT_VARCHAR"
	Member "SQLTStrings"
	Member "Stream"
	Member "String"
	Member "test"
	Member "Time"
	Member "TimeStamp"
Object "ADBE"
	Member "LANGUAGE"
	Member "PMD_Need_Version"
	Member "Reader_Need_Version"
	Member "Reader_string_Need_New_Version_Msg"
	Member "Reader_Value_Asked"
	Member "Reader_Value_New_Version_URL"
	Member "SYSINFO"
	Member "Viewer_Need_Version"
	Member "Viewer_string_PMD"
	Member "Viewer_string_PMD_Old"
	Member "Viewer_string_Title"
	Member "Viewer_string_Update_Desc"
	Member "Viewer_Value_Asked"
	Member "Viewer_Value_New_Version_URL"
Object "ADMDialog"
	Member "enable"
	Member "end"
	Member "focus"
	Member "insertEntryInList"
	Member "insertSeparatorEntryInList"
	Member "load"
	Member "makeCancel"
	Member "makeDefault"
	Member "makeLink"
	Member "removeAllEntriesFromList"
	Member "resize"
	Member "setForeColorRed"
	Member "store"
	Member "visible"
Object "Aggregate"
	Member "__NOPROPS__"
Object "AggregateFormWorkflowInfo"
	Member "sectionFeed"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setHandler"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

Object "AggregateReviewInfo"
	Member "sectionFeed"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setHandler"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

Object "Alert"
	Member "doc"
	Member "error"
	Member "errorText"
	Member "fileName"
	Member "fromUser"
	Member "selection"
	Member "type"
Object "Alerter"
	Member "dispatch"
Object "align"
	Member "bottom"
	Member "center"
	Member "left"
	Member "right"
	Member "top"
Object "Annot3D"
	Member "activated"
	Member "context3D"
	Member "innerRect"
	Member "name"
	Member "page"
	Member "rect"
Object "annotAttachment"
	Member "creationDate"
	Member "contentStream"
	Member "MIMEType"
	Member "modDate"
	Member "name"
	Member "path"
	Member "size"
	Member "toString"
	Member "valueOf"
Object "AnnotRichMedia"
	Member "activated"
	Member "callAS"
	Member "context3D"
	Member "name"
	Member "page"
	Member "rect"
	Member "subtype"
Object "AnyName"
	Member "__NOPROPS__"
Object "App"
	Member "activeDocs"
	Member "addMenuItem"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Console\Exec
			Event: App\Init

	Member "addressBookAvailable"
	Member "addSubMenu"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Console\Exec
			Event: App\Init

	Member "addToolButton"
	Member "AGMversion"
	Member "alert"
	Member "beep"
	Member "beginPriv"
	Member "browseForDoc"
		Security Priviledged for Method, have a list of allowed Events:
			Event: App\Init
			Event: Console\Exec

	Member "browseForMultipleDocs"
		Security Priviledged for Method, have a list of allowed Events:
			Event: App\Init
			Event: Console\Exec

	Member "calculate"
	Member "capabilities"
	Member "clearInterval"
	Member "clearTimeOut"
	Member "constants"
	Member "CTversion"
	Member "doc"
	Member "endPriv"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "execDialog"
	Member "execMenuItem"
	Member "findComponent"
	Member "focusRect"
	Member "formsVersion"
	Member "fromPDFConverters"
	Member "fs"
	Member "fsClick"
	Member "fsColor"
	Member "fsCursor"
	Member "fsEscape"
	Member "fsLoop"
	Member "fsTimeDelay"
	Member "fsTransition"
	Member "fsUsePageTiming"
	Member "fsUseTimer"
	Member "fullscreen"
	Member "getNthPlugInName"
	Member "getPath"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getResolvedAddresses"
	Member "getString"
	Member "goBack"
	Member "goForward"
	Member "hideMenuItem"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Console\Exec
			Event: App\Init

	Member "hideToolbarButton"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Console\Exec
			Event: App\Init

	Member "ignoreNextDoc"
	Member "ignoreXFA"
	Member "isValidSaveLocation"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "language"
	Member "launchURL"
	Member "listMenuItems"
	Member "listToolbarButtons"
	Member "loadPolicyFile"
	Member "mailGetAddrs"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "mailMsg"
	Member "mailMsgWithAttachment"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "measureDialog"
	Member "media"
	Member "monitors"
	Member "newCollection"
	Member "newDoc"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "newFDF"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "numPlugIns"
	Member "openDoc"
	Member "openFDF"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "openInPlace"
	Member "OSversion"
	Member "platform"
	Member "plugIns"
	Member "popUpMenu"
	Member "popUpMenuEx"
	Member "printColorProfiles"
	Member "printerNames"
	Member "reloadJSFiles"
	Member "removeToolButton"
	Member "response"
	Member "runtimeHighlight"
	Member "runtimeHighlightColor"
	Member "setInterval"
	Member "setProfile"
	Member "setTimeOut"
	Member "thermometer"
	Member "toolbar"
	Member "toolbarHorizontal"
	Member "toolbarVertical"
	Member "trustedFunction"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "trustPropagatorFunction"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "user"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "Username"
	Member "viewerType"
	Member "viewerVariation"
	Member "Viewerversion"
	Member "viewerVersion"
Object "AppMedia"
	Member "addStockEvents"
	Member "alertFileNotFound"
	Member "alertSelectFailed"
	Member "align"
	Member "argsDWIM"
	Member "canPlayOrAlert"
	Member "canResize"
	Member "closeReason"
	Member "computeFloatWinRect"
	Member "constrainRectToScreen"
	Member "createPlayer"
	Member "defaultVisible"
	Member "getAltTextData"
	Member "getAltTextSettings"
	Member "getAnnotStockEvents"
	Member "getAnnotTraceEvents"
	Member "getPlayers"
	Member "getPlayerStockEvents"
	Member "getPlayerTraceEvents"
	Member "getRenditionSettings"
	Member "getURLData"
	Member "getURLSettings"
	Member "getWindowBorderSize"
	Member "ifOffScreen"
	Member "layout"
	Member "monitorType"
	Member "openCode"
	Member "openPlayer"
	Member "over"
	Member "pageEventNames"
	Member "priv"
	Member "raiseCode"
	Member "raiseSystem"
	Member "removeStockEvents"
	Member "renditionType"
	Member "startPlayer"
	Member "status"
	Member "trace"
	Member "version"
	Member "windowType"
Object "AppMediaPriv"
	Member "throwBadArgs"
Object "Array"
	Member "concat"
	Member "every"
	Member "filter"
	Member "forEach"
	Member "indexOf"
	Member "join"
	Member "lastIndexOf"
	Member "map"
	Member "pop"
	Member "push"
	Member "reverse"
	Member "shift"
	Member "some"
	Member "sort"
	Member "splice"
	Member "toLocaleString"
	Member "unshift"
Object "AttributeName"
	Member "__NOPROPS__"
Object "bookletBindings"
	Member "Left"
	Member "LeftTall"
	Member "Right"
	Member "RightTall"
Object "bookletDuplexModes"
	Member "BackSideOnly"
	Member "BothSides"
	Member "FrontSideOnly"
Object "Bookmark"
	Member "children"
	Member "color"
		Security Priviledged for Setter - (property?)
	Member "createChild"
		Security Priviledged for Method, have a list of allowed Events:
	Member "doc"
	Member "execute"
	Member "insertChild"
		Security Priviledged for Method, have a list of allowed Events:
	Member "name"
		Security Priviledged for Setter - (property?)
	Member "open"
	Member "parent"
	Member "remove"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setAction"
		Security Priviledged for Method, have a list of allowed Events:
	Member "style"
		Security Priviledged for Setter - (property?)
	Member "toString"
	Member "valueOf"
Object "Boolean"
	Member "__NOPROPS__"
Object "Breakpoint"
	Member "condition"
	Member "fileName"
	Member "lineNum"
Object "Call"
	Member "__NOPROPS__"
Object "capabilities"
	Member "viewer"
Object "capabilities_viewer"
	Member "sponsoredContent"
	Member "sponsoredContentVersion"
Object "Catalog"
	Member "getIndex"
		Security Priviledged for Method, have a list of allowed Events:
	Member "isIdle"
		Security Priviledged for Getter - (property?)
	Member "jobs"
		Security Priviledged for Getter - (property?)
	Member "remove"
		Security Priviledged for Method, have a list of allowed Events:
Object "CatalogJob"
	Member "path"
	Member "status"
	Member "type"
Object "Certificate"
	Member "binary"
		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "issuerDN"
	Member "keyUsage"
	Member "MD5Hash"
	Member "privateKeyValidityEnd"
	Member "privateKeyValidityStart"
	Member "serialNumber"
	Member "SHA1Hash"
	Member "subjectCN"
	Member "subjectDN"
	Member "toString"
	Member "ubRights"
	Member "usage"
	Member "validityEnd"
	Member "validityStart"
	Member "valueOf"
Object "CertificateSpecifier"
	Member "flags"
	Member "Issuer"
	Member "old"
	Member "subject"
	Member "url"
Object "Checkbox"
	Member "bAfterValue"
	Member "bInitialValue"
	Member "cMsg"
Object "Collab"
	Member "addAnnotStore"
	Member "addDocToDocsOpenedByWizard"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addedAnnotCount"
	Member "addReviewFolder"
	Member "addReviewServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addStateModel"
	Member "AFCheckSubmitButtonStatus"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "AFPrepareFormForDistribution"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "alertWithHelp"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "allReviewServers"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "animateSyncButton"
	Member "AVUMAddStringToPayloadWrapper"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "AVUMEndPayloadWrapper"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "AVUMLogEventWrapper"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "AVUMStartPayloadWrapper"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "beginInitiatorMailOperation"
	Member "bringToFront"
	Member "browseForFolder"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "browseForNetworkFolder"
	Member "canCollapseTrackerSelection"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "canExpandTrackerSelection"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "canProxy"
	Member "collapseTrackerSelection"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "convertDIPathToPlatformPath"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "convertMappedDrivePathToSMBURL"
	Member "convertPlatformPathToDIPath"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "copyMe"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "cosObj2Stream"
	Member "createAnnotStore"
	Member "createUniqueDocID"
	Member "dcSignup"
	Member "debugPrintln"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "defaultStore"
	Member "disableDocCentreSignup"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "docCenterHomeURL"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "docCenterURL"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "docID"
	Member "documentToStream"
		Security Priviledged for Method, have a list of allowed Events:
	Member "drivers"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "dumpOfflineDocs"
	Member "enableFinalApprovalEmail"
	Member "endInitiatorMailOperation"
	Member "expandTrackerSelection"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "finalApprovalEmailEnabled"
	Member "GetActiveDocIW"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getAggregateReviewInfo"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getAlwaysUseServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getCCaddr"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getCustomEmailMessage"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getDateAndTime"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getDebugHostedServicesSettings"
	Member "getDefaultDateAndTime"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getDocCenterReviewServer"
	Member "getEmailDistributionReviewServer"
	Member "getFdfUrl"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getFullyQualifiedHostname"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getIcon"
	Member "getIdentity"
	Member "getNumberOfReviewsOnServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getProgressInfo"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getProxy"
	Member "getReviewError"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getReviewFolder"
	Member "getReviewFolders"
	Member "getReviewInfo"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getReviewState"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getServiceURL"
	Member "getStateModels"
	Member "getStoreFSBased"
	Member "getStoreNoSettings"
	Member "getStoreSettings"
	Member "getUserIDFromStore"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "goBackOnline"
	Member "hashString"
	Member "hasInitiatorEmailRequest"
	Member "hasReviewCommentRepositoryIntact"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "hasReviewDeadline"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "hasSynchonizer"
	Member "haveOfflineReviews"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "haveReviews"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "init"
		Security Priviledged for Method, have a list of allowed Events:
	Member "initiatorEmail"
	Member "invite"
	Member "isApprovalWorkflow"
	Member "isDisplayBezelEnabled"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "isDocCenterURL"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "isDocCentreSignupDisabled"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "isDocCtrInitAvailable"
	Member "isDocDirty"
	Member "isDocReadOnly"
	Member "isEmailReview"
	Member "isFirstLaunch"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "isOfflineReview"
	Member "isOnlineReview"
	Member "isOutlook"
	Member "isPathWritable"
	Member "isSharedReview"
	Member "isSynchronizerIconShown"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "isUbiquitized"
	Member "lastBBRURL"
	Member "launchHelpViewer"
		Security Priviledged for Method, have a list of allowed Events:
	Member "makeAllCommentsReadOnly"
	Member "maxPDFCommentsSize"
	Member "modifiedAnnotCount"
	Member "mountSMBURL"
	Member "newWrStreamToCosObj"
	Member "privateAnnotsAllowed"
	Member "registerApproval"
	Member "registerProxy"
	Member "registerReview"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removeApprovalDocScript"
	Member "removeDocsOpenedByWizard"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "removeMultipleSelectedReviewsInTracker"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "removeReviewFolder"
	Member "removeStateModel"
	Member "returnToInitiator"
	Member "reviewersEmail"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "reviewServers"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "saveTrackerHTML"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setAlwaysUseServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setCustomEmailMessage"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setDebugHostedServicesSettings"
	Member "setDefaultReviewServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "inEmailWorkflow"
	Member "setReviewFolder"
	Member "setReviewFolderForMultipleReviews"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setReviewRespondedDate"
	Member "setStoreFSBased"
	Member "setStoreNoSettings"
	Member "setStoreSettings"
	Member "shareFile"
	Member "shareFileBezel"
	Member "showAnnotToolsWhenNoCollab"
	Member "showBasicAuditTrail"
	Member "stream2CosObj"
	Member "streamToDocument"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "stringToUTF8"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "swAcceptTOU"
	Member "swConnect"
	Member "swSendVerifyEmail"
	Member "sync"
		Security Priviledged for Method, have a list of allowed Events:
	Member "takeOwnershipAndPublishComments"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "takeOwnershipOfComments"
	Member "testRWF"
	Member "testShareFileHFT"
	Member "testSW"
	Member "testUploadFileHFT"
	Member "testWF"
	Member "testWFI"
	Member "unregisterApproval"
	Member "unregisterOffline"
	Member "unregisterReview"
	Member "unsetAlwaysUseServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "unsetFirstLaunch"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "updateMountInfo"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "uriConvertReviewSource"
	Member "uriCreateFolder"
	Member "uriDeleteFile"
	Member "uriDeleteFolder"
	Member "uriEncode"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "uriEnumerateFiles"
	Member "uriNormalize"
	Member "uriPutData"
	Member "uriToDIPath"
	Member "URL2PathFragment"
	Member "user"
Object "Collection"
	Member "addField"
	Member "fields"
	Member "getField"
	Member "initialDoc"
	Member "initialView"
	Member "removeField"
Object "CollectionField"
	Member "name"
	Member "order"
	Member "readOnly"
	Member "sort"
	Member "text"
	Member "type"
	Member "visible"
Object "color"
	Member "black"
	Member "blue"
	Member "convert"
	Member "cyan"
	Member "dkGray"
	Member "equal"
	Member "gray"
	Member "green"
	Member "ltGray"
	Member "magenta"
	Member "red"
	Member "transparent"
	Member "white"
	Member "yellow"
Object "colorConvertAction"
	Member "action"
	Member "alias"
	Member "colorantName"
	Member "constants"
	Member "convertIntent"
	Member "convertProfile"
	Member "embed"
	Member "isProcessColor"
	Member "matchAttributesAll"
	Member "matchAttributesAny"
	Member "matchIntent"
	Member "matchSpaceTypeAll"
	Member "matchSpaceTypeAny"
	Member "preserveBlack"
	Member "useBlackPointCompensation"
Object "colorOverrides"
	Member "auto"
	Member "gray"
	Member "mono"
Object "Column"
	Member "columnNum"
	Member "name"
	Member "type"
	Member "typeName"
	Member "value"
Object "ColumnInfo"
	Member "description"
	Member "name"
	Member "type"
	Member "typeName"
Object "ConfigSuiteObj"
	Member "__ALLPROPS__"
Object "Connection"
	Member "close"
	Member "getColumnList"
	Member "getTableList"
	Member "newStatement"
Object "Console"
	Member "clear"
	Member "hide"
	Member "println"
	Member "show"
	Member "stderrOutput"
Object "constants"
	Member "actions"
	Member "align"
	Member "bookletBindings"
	Member "bookletDuplexModes"
	Member "colorOverrides"
	Member "duplexTypes"
	Member "flagValues"
	Member "fontPolicies"
	Member "handling"
	Member "intents"
	Member "interactionLevel"
	Member "nUpPageOrders"
	Member "objectFlags"
	Member "outputTypes"
	Member "printContents"
	Member "rasterFlagValues"
	Member "renderingIntents"
	Member "spaceFlags"
	Member "states"
	Member "subsets"
	Member "tileMarks"
	Member "usages"
Object "CosObj"
	Member "toString"
	Member "valueOf"
Object "CreatedAVView"
	Member "enable"
	Member "end"
	Member "getFeed"
	Member "getOptions"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getSelection"
	Member "isFeedSelection"
	Member "isGroupSelection"
	Member "isItemSelection"
	Member "load"
	Member "store"
Object "Data"
	Member "creationDate"
	Member "description"
	Member "getFieldValue"
	Member "MIMEType"
	Member "modDate"
	Member "name"
	Member "path"
	Member "setFieldValue"
	Member "size"
	Member "toString"
	Member "valueOf"
Object "DataSourceInfo"
	Member "description"
	Member "name"
Object "Date"
	Member "getDate"
	Member "getDay"
	Member "getFullYear"
	Member "getHours"
	Member "getMilliseconds"
	Member "getMinutes"
	Member "getMonth"
	Member "getSeconds"
	Member "getTime"
	Member "getTimezoneOffset"
	Member "getUTCDate"
	Member "getUTCDay"
	Member "getUTCFullYear"
	Member "getUTCHours"
	Member "getUTCMilliseconds"
	Member "getUTCMinutes"
	Member "getUTCMonth"
	Member "getUTCSeconds"
	Member "getYear"
	Member "setDate"
	Member "setFullYear"
	Member "setHours"
	Member "setMilliseconds"
	Member "setMinutes"
	Member "setMonth"
	Member "setSeconds"
	Member "setTime"
	Member "setUTCDate"
	Member "setUTCFullYear"
	Member "setUTCHours"
	Member "setUTCMilliseconds"
	Member "setUTCMinutes"
	Member "setUTCMonth"
	Member "setUTCSeconds"
	Member "setYear"
	Member "toDateString"
	Member "toLocaleDateString"
	Member "toLocaleFormat"
	Member "toLocaleString"
	Member "toLocaleTimeString"
	Member "toTimeString"
	Member "toUTCString"
Object "Dbg"
	Member "bps"
		Security Priviledged for Getter - (property?)
		Security Priviledged for Setter - (property?)
	Member "c"
		Security Priviledged for Method, have a list of allowed Events:
	Member "cb"
		Security Priviledged for Method, have a list of allowed Events:
	Member "q"
		Security Priviledged for Method, have a list of allowed Events:
	Member "sb"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Console\Exec

	Member "si"
		Security Priviledged for Method, have a list of allowed Events:
	Member "sn"
		Security Priviledged for Method, have a list of allowed Events:
	Member "so"
		Security Priviledged for Method, have a list of allowed Events:
	Member "sv"
		Security Priviledged for Method, have a list of allowed Events:
Object "debuggerGlobal"
	Member "clearInspector"
	Member "clearStack"
	Member "displayAlert"
	Member "getOrigName"
	Member "getParentList"
	Member "getString"
	Member "getThrowMode"
	Member "getUniqueName"
	Member "openDebugger"
	Member "printConsole"
	Member "printFunction"
	Member "printInspector"
	Member "printStack"
	Member "printWatch"
	Member "regBreakpoint"
	Member "resumeCode"
	Member "saveBreakpoints"
	Member "selectScriptLine"
	Member "suspendThread"
	Member "updateBreakpoint"
	Member "updateStopIcon"
Object "Dest"
	Member "__NOPROPS__"
Object "DialogDescription"
	Member "align_children"
	Member "char_height"
	Member "char_width"
	Member "elements"
	Member "first_tab"
	Member "height"
	Member "name"
	Member "width"
Object "DialogElement"
	Member "align_children"
	Member "alignment"
	Member "bold"
	Member "cancel_name"
	Member "char_height"
	Member "char_width"
	Member "font"
	Member "group_id"
	Member "height"
	Member "italic"
	Member "item_id"
	Member "multiline"
	Member "name"
	Member "next_tab"
	Member "ok_name"
	Member "other_name"
	Member "password"
	Member "PopupEdit"
	Member "readonly"
	Member "SpinEdit"
	Member "type"
	Member "width"
Object "DialogHandler"
	Member "commit"
	Member "description"
	Member "destroy"
	Member "initialize"
	Member "ItemID"
	Member "validate"
Object "DirConnection"
	Member "canDoCustomSearch"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "canDoCustomUISearch"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "canDoStandardSearch"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "canList"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "groups"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "name"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "search"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "setOutputFields"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "toString"
	Member "uiName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "valueOf"
Object "Directory"
	Member "connect"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "info"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "toString"
	Member "valueOf"
Object "DirectoryInformation"
	Member "dirStdEntryDirType"
	Member "dirStdEntryID"
	Member "dirStdEntryName"
	Member "dirStdEntryPrefDirhandlerID"
	Member "dirStdEntryVersion"
	Member "maxNumEntries"
	Member "port"
	Member "searchBase"
	Member "server"
	Member "timeout"
Object "DiscoveryQuery"
	Member "stop"
Object "DiscoveryResolve"
	Member "stop"
Object "DisplayOptions"
	Member "bAllowImportFromFile"
	Member "bAllowPermGroups"
	Member "bPlaintextMetadata"
	Member "bRequireEmail"
	Member "bRequireEncryptionCert"
	Member "bUserCert"
	Member "cNote"
	Member "cTitle"
Object "Doc"
	Member "ADBE"
	Member "addAnnot"
	Member "addField"
		Security Priviledged for Method, have a list of allowed Events:
	Member "addIcon"
		Security Priviledged for Method, have a list of allowed Events:
	Member "addLink"
		Security Priviledged for Method, have a list of allowed Events:
	Member "addNewField"
	Member "addRecipientListCryptFilter"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "addRequirement"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addScript"
		Security Priviledged for Method, have a list of allowed Events:
	Member "addThumbnails"
		Security Priviledged for Method, have a list of allowed Events:
	Member "addWatermarkFromFile"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addWatermarkFromText"
		Security Priviledged for Method, have a list of allowed Events:
	Member "addWatermarkFromTextNoPerms"
	Member "addWeblinks"
		Security Priviledged for Method, have a list of allowed Events:
	Member "annotFilter"
	Member "app"
	Member "applyRedactions"
	Member "appRightsSign"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "appRightsValidate"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "author"
		Security Priviledged for Setter - (property?)
	Member "baseURL"
		Security Priviledged for Setter - (property?)
	Member "bookmarkRoot"
	Member "bringToFront"
	Member "calculate"
	Member "calculateNow"
	Member "certified"
	Member "certifyInvisibleSign"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "closed"
	Member "closeDoc"
	Member "Collab"
	Member "collection"
	Member "colorConvertPage"
		Security Priviledged for Method, have a list of allowed Events:
	Member "createDataObject"
		Security Priviledged for Method, have a list of allowed Events:
	Member "createIcon"
	Member "createTemplate"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "creationDate"
		Security Priviledged for Setter - (property?)
	Member "creator"
		Security Priviledged for Setter - (property?)
	Member "dataObjects"
	Member "delay"
	Member "deleteIcon"
		Security Priviledged for Method, have a list of allowed Events:
	Member "deletePages"
		Security Priviledged for Method, have a list of allowed Events:
	Member "deleteSound"
		Security Priviledged for Method, have a list of allowed Events:
	Member "DigSigGetUBRightsTest"
	Member "DigSigUbiquitizeTest"
	Member "DigSigUnUbiquitizeTest"
	Member "dirty"
	Member "disableWindows"
		Security Priviledged for Method, have a list of allowed Events:
			Event: External\Exec

	Member "disclosed"
		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: Page\Open
			Event: Doc\Open

	Member "docID"
	Member "documentFileName"
	Member "DoOcr"
	Member "DoTiffOCR"
	Member "DoOptimizePDF"
	Member "DoPreflightPDF"
	Member "dynamicXFAForm"
	Member "embedDocAsDataObject"
		Security Priviledged for Method, have a list of allowed Events:
	Member "embedOutputIntent"
	Member "enableWindows"
		Security Priviledged for Method, have a list of allowed Events:
			Event: External\Exec

	Member "encryptForRecipients"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "encryptUsingPolicy"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "exportAsFDF"
	Member "exportAsFDFStr"
	Member "exportAsText"
	Member "exportAsTextStr"
	Member "exportAsXFAStr"
	Member "exportAsXFDF"
	Member "exportAsXFDFStr"
	Member "exportDataObject"
		Security Priviledged for Method, have a list of allowed Events:
	Member "exportXFAData"
		Security Priviledged for Method, have a list of allowed Events:
	Member "external"
	Member "extractPages"
	Member "FileSaveTests"
	Member "filesize"
	Member "flattenPages"
		Security Priviledged for Method, have a list of allowed Events:
	Member "getAnnot"
	Member "getAnnot3D"
	Member "getAnnotRichMedia"
	Member "getAnnots"
	Member "getAnnots3D"
	Member "getAnnotsRichMedia"
	Member "getColorConvertAction"
		Security Priviledged for Method, have a list of allowed Events:
	Member "getDataObject"
	Member "getDataObjectContents"
	Member "getField"
	Member "getIcon"
	Member "getLegalWarnings"
	Member "getLinks"
	Member "getModifications"
		Security Priviledged for Method, have a list of allowed Events:
	Member "getNthFieldName"
	Member "getNthIconName"
	Member "getNthTemplate"
	Member "getOCGOrder"
	Member "getOCGs"
	Member "getPageBox"
	Member "getPageLabel"
	Member "getPageNthWord"
		Security Priviledged for Method, have a list of allowed Events:
	Member "getPageNthWordQuads"
		Security Priviledged for Method, have a list of allowed Events:
	Member "getPageNumWords"
		Security Priviledged for Method, have a list of allowed Events:
	Member "getPageRotation"
	Member "getPageTransition"
	Member "getPreflightAuditTrail"
	Member "getPrintParams"
	Member "getPrintSepsParams"
	Member "getSignatureStatus"
	Member "getSound"
	Member "getTemplate"
	Member "getUIPerms"
	Member "getURL"
	Member "gotoNamedDest"
	Member "hidden"
	Member "hostContainer"
	Member "icons"
	Member "importAnFDF"
		Security Priviledged for Method, have a list of allowed Events:
	Member "importAnXFDF"
		Security Priviledged for Method, have a list of allowed Events:
	Member "importDataObject"
		Security Priviledged for Method, have a list of allowed Events:
	Member "importIcon"
		Security Priviledged for Method, have a list of allowed Events:
	Member "importSound"
		Security Priviledged for Method, have a list of allowed Events:
	Member "importTextData"
		Security Priviledged for Method, have a list of allowed Events:
	Member "importXFAData"
		Security Priviledged for Method, have a list of allowed Events:
	Member "info"
	Member "innerAppWindowRect"
	Member "innerDocWindowRect"
	Member "insertPages"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "isInCollection"
	Member "isInProtectedView"
	Member "isModal"
	Member "keywords"
		Security Priviledged for Setter - (property?)
	Member "layout"
	Member "mailDoc"
	Member "mailForm"
		Security Priviledged for Method, have a list of allowed Events:
	Member "media"
	Member "metadata"
		Security Priviledged for Setter - (property?)
	Member "modDate"
		Security Priviledged for Setter - (property?)
	Member "mouseX"
	Member "mouseY"
	Member "movePage"
		Security Priviledged for Method, have a list of allowed Events:
	Member "newPage"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "noautocomplete"
	Member "nocache"
	Member "numFields"
	Member "numIcons"
	Member "numPages"
	Member "numTemplates"
	Member "openDataObject"
	Member "outerAppWindowRect"
	Member "outerDocWindowRect"
	Member "pageNum"
	Member "pageWindowRect"
	Member "pane"
	Member "path"
	Member "permStatusReady"
	Member "preflight"
	Member "print"
		Security Priviledged for Method, have a list of allowed Events:
	Member "printex"
	Member "printSeps"
		Security Priviledged for Method, have a list of allowed Events:
	Member "printSepsWithParams"
	Member "printWithParams"
	Member "producer"
		Security Priviledged for Setter - (property?)
	Member "removeDataObject"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removeField"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removeIcon"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removeLinks"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removePreflightAuditTrail"
	Member "removeRequirement"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "removeScript"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removeTemplate"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "removeThumbnails"
		Security Priviledged for Method, have a list of allowed Events:
	Member "removeWeblinks"
		Security Priviledged for Method, have a list of allowed Events:
	Member "replacePages"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "requestPermission"
	Member "requiresFullSave"
	Member "resetForm"
		Security Priviledged for Method, have a list of allowed Events:
	Member "rightsManagement"
	Member "SAPCheckFields"
	Member "SAPDisableLogging"
	Member "SAPEnableLogging"
	Member "SAPLog"
	Member "SAPSetDocDirty"
	Member "SAPSubmit"
	Member "SAPToolbarHide"
	Member "SAPValueHelp"
	Member "saveAs"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "scroll"
	Member "securityHandler"
	Member "selectedAnnots"
	Member "selectPageNthWord"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setAction"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setDataObjectContents"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setOCGOrder"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setPageAction"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setPageBoxes"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setPageLabels"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setPageRotations"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setPageTabOrder"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setPageTransitions"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setUIPerms"
	Member "setUserPerms"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "sounds"
	Member "spawnPageFromTemplate"
		Security Priviledged for Method, have a list of allowed Events:
	Member "spellDictionaryOrder"
	Member "spellLanguageOrder"
	Member "stampAPFromPage"
		Security Priviledged for Method, have a list of allowed Events:
	Member "subject"
		Security Priviledged for Setter - (property?)
	Member "submitForm"
	Member "syncAnnotScan"
	Member "templates"
	Member "timestampSign"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "title"
		Security Priviledged for Setter - (property?)
	Member "toString"
	Member "transitionToState"
		Security Priviledged for Method, have a list of allowed Events:
	Member "URL"
	Member "validatePreflightAuditTrail"
	Member "valueOf"
	Member "view"
	Member "viewState"
	Member "wireframe"
	Member "xfa"
	Member "XFAForeground"
	Member "zoom"
	Member "zoomType"
Object "DocMedia"
	Member "adbeDoc"
	Member "canPlay"
	Member "deleteRendition"
	Member "getAnnot"
	Member "getAnnots"
	Member "getOpenPlayers"
	Member "getRendition"
	Member "newPlayer"
Object "duplexTypes"
	Member "DontCare"
	Member "DuplexFlipLongEdge"
	Member "DuplexFlipShortEdge"
	Member "Simplex"
Object "DVA"
	Member "AnalyzeDocument"
Object "Error"
	Member "Error"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "stack"
	Member "toString"
Object "EvalError"
	Member "EvalError"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "stack"
Object "Event"
	Member "change"
	Member "changeEx"
	Member "commitKey"
	Member "fieldFull"
	Member "keyDown"
	Member "modifier"
	Member "name"
	Member "rc"
	Member "richChange"
	Member "richChangeEx"
	Member "richValue"
	Member "selEnd"
	Member "selStart"
	Member "shift"
	Member "silenceErrors"
	Member "source"
	Member "target"
	Member "targetName"
	Member "type"
	Member "value"
	Member "willCommit"
Object "EventListener"
	Member "afterBlur"
	Member "afterClose"
	Member "afterDestroy"
	Member "afterDone"
	Member "afterError"
	Member "afterEscape"
	Member "afterEveryEvent"
	Member "afterFocus"
	Member "afterPause"
	Member "afterPlay"
	Member "afterReady"
	Member "afterScript"
	Member "afterSeek"
	Member "afterStatus"
	Member "afterStop"
	Member "onBlur"
	Member "onClose"
	Member "onDestroy"
	Member "onDone"
	Member "onError"
	Member "onEscape"
	Member "onEveryEvent"
	Member "onFocus"
	Member "onGetRect"
	Member "onPause"
	Member "onPlay"
	Member "onReady"
	Member "onScript"
	Member "onSeek"
	Member "onStatus"
	Member "onStop"
Object "Events"
	Member "add"
	Member "dispatch"
	Member "remove"
Object "ExerciserObj"
	Member "__ALLPROPS__"
Object "FDF"
	Member "addContact"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addEmbeddedFile"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addRequest"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "close"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "deleteOption"
		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "isSigned"
		Security Priviledged for Getter - (property?)
	Member "mail"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "numEmbeddedFiles"
		Security Priviledged for Getter - (property?)
	Member "save"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signatureClear"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signatureSign"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signatureValidate"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "toString"
	Member "valueOf"
Object "Field"
	Member "alignment"
		Security Priviledged for Setter - (property?)
	Member "bgColor"
		Security Priviledged for Setter - (property?)
	Member "borderColor"
		Security Priviledged for Setter - (property?)
	Member "borderStyle"
		Security Priviledged for Setter - (property?)
	Member "borderWidth"
		Security Priviledged for Setter - (property?)
	Member "browseForFileToSubmit"
		Security Priviledged for Method, have a list of allowed Events:
	Member "buttonAlignX"
		Security Priviledged for Setter - (property?)
	Member "buttonAlignY"
		Security Priviledged for Setter - (property?)
	Member "buttonFitBounds"
		Security Priviledged for Setter - (property?)
	Member "buttonGetCaption"
	Member "buttonGetIcon"
	Member "buttonImportIcon"
	Member "buttonPosition"
		Security Priviledged for Setter - (property?)
	Member "buttonScaleHow"
		Security Priviledged for Setter - (property?)
	Member "buttonScaleWhen"
		Security Priviledged for Setter - (property?)
	Member "buttonSetCaption"
		Security Priviledged for Method, have a list of allowed Events:
	Member "buttonSetIcon"
		Security Priviledged for Method, have a list of allowed Events:
	Member "calcOrderIndex"
		Security Priviledged for Setter - (property?)
	Member "charLimit"
		Security Priviledged for Setter - (property?)
	Member "checkThisBox"
		Security Priviledged for Method, have a list of allowed Events:
	Member "clear"
		Security Priviledged for Method, have a list of allowed Events:
	Member "clearItems"
		Security Priviledged for Method, have a list of allowed Events:
	Member "comb"
		Security Priviledged for Setter - (property?)
	Member "commitOnSelChange"
		Security Priviledged for Setter - (property?)
	Member "currentValueIndices"
		Security Priviledged for Setter - (property?)
	Member "defaultIsChecked"
		Security Priviledged for Method, have a list of allowed Events:
	Member "defaultStyle"
	Member "defaultValue"
		Security Priviledged for Setter - (property?)
	Member "delay"
	Member "deleteItemAt"
		Security Priviledged for Method, have a list of allowed Events:
	Member "display"
	Member "doc"
	Member "doNotScroll"
		Security Priviledged for Setter - (property?)
	Member "doNotSpellCheck"
		Security Priviledged for Setter - (property?)
	Member "editable"
		Security Priviledged for Setter - (property?)
	Member "exportValues"
		Security Priviledged for Setter - (property?)
	Member "fgColor"
		Security Priviledged for Setter - (property?)
	Member "fileSelect"
		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "fillColor"
		Security Priviledged for Setter - (property?)
	Member "getArray"
	Member "getItemAt"
	Member "getLock"
	Member "hidden"
		Security Priviledged for Setter - (property?)
	Member "highlight"
		Security Priviledged for Setter - (property?)
	Member "insertItemAt"
		Security Priviledged for Method, have a list of allowed Events:
	Member "isBoxChecked"
	Member "isDefaultChecked"
	Member "lineWidth"
		Security Priviledged for Setter - (property?)
	Member "multiline"
		Security Priviledged for Setter - (property?)
	Member "multipleSelection"
		Security Priviledged for Setter - (property?)
	Member "name"
	Member "numItems"
	Member "page"
	Member "password"
		Security Priviledged for Setter - (property?)
	Member "print"
		Security Priviledged for Setter - (property?)
	Member "radiosInUnison"
		Security Priviledged for Setter - (property?)
	Member "readonly"
		Security Priviledged for Setter - (property?)
	Member "rect"
		Security Priviledged for Setter - (property?)
	Member "required"
		Security Priviledged for Setter - (property?)
	Member "richText"
		Security Priviledged for Setter - (property?)
	Member "richValue"
		Security Priviledged for Setter - (property?)
	Member "rotation"
		Security Priviledged for Setter - (property?)
	Member "setAction"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setExportValues"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setFocus"
	Member "setItems"
		Security Priviledged for Method, have a list of allowed Events:
	Member "setLock"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signatureGetModifications"
	Member "signatureGetSeedValue"
	Member "signatureInfo"
	Member "signatureSetSeedValue"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signatureSign"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signatureValidate"
	Member "signatureAddLTV"
	Member "strokeColor"
		Security Priviledged for Setter - (property?)
	Member "style"
		Security Priviledged for Setter - (property?)
	Member "submitName"
		Security Priviledged for Setter - (property?)
	Member "textColor"
		Security Priviledged for Setter - (property?)
	Member "textFont"
		Security Priviledged for Setter - (property?)
	Member "textSize"
		Security Priviledged for Setter - (property?)
	Member "type"
	Member "userName"
		Security Priviledged for Setter - (property?)
	Member "value"
		Security Priviledged for Setter - (property?)
	Member "valueAsString"
Object "flagValues"
	Member "applyOverPrint"
	Member "applySoftProofSettings"
	Member "applyWorkingColorSpaces"
	Member "emitCJKTTasT2"
	Member "emitFlatness"
	Member "emitFormsAsPSForms"
	Member "emitHalftones"
	Member "emitPostScriptXObjects"
	Member "maxJP2KRes"
	Member "setPageSize"
	Member "suppressBG"
	Member "suppressCenter"
	Member "suppressCJKFontSubst"
	Member "suppressCropClip"
	Member "suppressRotate"
	Member "suppressTransfer"
	Member "suppressUCR"
	Member "usePrintersMarks"
	Member "useTrapAnnots"
Object "fontPolicies"
	Member "everyPage"
	Member "jobStart"
	Member "pageRange"
Object "FormWorkflow"
	Member "addFormWorkflowFolder"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getAggregateFormWorkflowInfo"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getFormWorkflowError"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getFormWorkflowFolders"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getFormWorkflowInfo"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getNumberOfFormWorkflowsOnServer"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "haveFormWorkflows"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "removeFormWorkflowFolder"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "removeMultipleSelectedFormWorkflowsInTracker"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setFormFolderForMultipleForms"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setFormWorkflowFolder"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "unregisterFormsWorkflow"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

Object "FormWorkflowInfo"
	Member "bAllowAnonymous"
	Member "bIsSuspended"
	Member "cAccessLevel"
	Member "cDistributedOn"
	Member "cDistributionMethod"
	Member "cDistributorEmail"
	Member "cDistributorName"
	Member "cError"
	Member "cFormHost"
	Member "cFormLocation"
	Member "cFormWorkflowID"
	Member "cLastOpenedOn"
	Member "cLastSubmittedOn"
	Member "cReceivedOn"
	Member "cResponsesLocation"
	Member "cState"
	Member "cStateAsPerWorkflowsFile"
	Member "nDistributedOn"
	Member "nNewResponses"
	Member "nReceivedOn"
	Member "nRecipients"
	Member "nResponses"
	Member "oRecipients"
	Member "oSubmissions"
	Member "setHandler"
Object "FSAnnotStore"
	Member "FSAnnotStore"
	Member "init"
	Member "sync"
Object "FullScreen"
	Member "backgroundColor"
	Member "clickAdvances"
	Member "cursor"
	Member "defaultTransition"
	Member "escapeExits"
	Member "isFullScreen"
	Member "loop"
	Member "timeDelay"
	Member "transitions"
	Member "usePageTiming"
	Member "useTimer"
Object "Function"
	Member "apply"
	Member "call"
	Member "defaultSettings"
	Member "fromCharCode"
	Member "now"
	Member "parse"
	Member "prototype"
	Member "setSettings"
	Member "settings"
	Member "thaw"
	Member "UTC"
Object "Global"
	Member "__ALLPROPS__"
	Member "ADBE_PMD_Check"
	Member "ADBE_PMD_Installed"
	Member "ADBE_PMD_NeedVersion"
	Member "ADBE_PMD_Version"
	Member "setPersistent"
	Member "subscribe"
Object "Group"
	Member "permissions"
	Member "userEntities"
Object "handling"
	Member "booklet"
	Member "fit"
	Member "none"
	Member "nUp"
	Member "shrink"
	Member "tileAll"
	Member "tileLarge"
Object "hostContainer"
	Member "messageHandler"
	Member "postMessage"
Object "HostedServices"
	Member "disconnect"
	Member "fileExists"
	Member "getAuthInfo"
	Member "getFullName"
	Member "getMatchingFiles"
	Member "getSessionInfo"
	Member "initiateWorkflow"
	Member "shareFile"
Object "Icon"
	Member "name"
	Member "toString"
	Member "valueOf"
Object "IconStream"
	Member "height"
	Member "read"
	Member "width"
Object "Identity"
	Member "corpAbbrev"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "corporation"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "department"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "email"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "firstName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "lastName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "loginName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

	Member "name"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "title"
Object "Import3D"
	Member "ExportIGES"
	Member "ExportPARA"
	Member "ExportPreset"
	Member "ExportSTEP"
	Member "ExportSTL"
	Member "ExportVRML"
	Member "GetAnimationStyle"
	Member "GetBrepCount"
	Member "GetCompressedBrepCount"
	Member "GetCompressedTessellationCount"
	Member "GetConversionTime"
	Member "GetKeyTime"
	Member "GetMaxPartSize"
	Member "GetMinPartSize"
	Member "GetNumCameras"
	Member "GetNumFaces"
	Member "GetNumKeys"
	Member "GetNumLevels"
	Member "GetNumLights"
	Member "GetNumMaterials"
	Member "GetNumMetaData"
	Member "GetNumNodes"
	Member "GetNumPMInodes"
	Member "GetNumTextures"
	Member "GetNumVertices"
	Member "GetNumViews"
	Member "GetPreset"
	Member "GetRegFlag"
	Member "GetStreamLength"
	Member "GetStreamType"
	Member "GetTessellationCount"
	Member "HasJavaScript"
	Member "ImportPreset"
	Member "IsTypeSupported"
	Member "Optimize"
	Member "SetToDefaults"
	Member "showDialog"
	Member "TestImport3D"
	Member "useJSSettingsFlag"
	Member "usePresetFlag"
	Member "usePresetValue"
Object "Index"
	Member "available"
	Member "build"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "name"
	Member "path"
	Member "selected"
Object "Info"
	Member "__ALLPROPS__"
	Member "Author"
	Member "Authors"
	Member "ContactEmail"
	Member "CreationDate"
	Member "Creator"
	Member "Keywords"
	Member "ModDate"
	Member "Producer"
	Member "Subject"
	Member "Title"
	Member "Trapped"
Object "intents"
	Member "design"
	Member "view"
Object "interactionLevel"
	Member "automatic"
	Member "full"
	Member "silent"
Object "InternalError"
	Member "extMessage"
	Member "fileName"
	Member "InternalError"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "stack"
Object "Jstests"
	Member "__ALLPROPS__"
Object "JSTInput"
	Member "__ALLPROPS__"
Object "JSTOutput"
	Member "__ALLPROPS__"
Object "Link"
	Member "borderColor"
		Security Priviledged for Setter - (property?)
	Member "borderWidth"
		Security Priviledged for Setter - (property?)
	Member "highlightMode"
		Security Priviledged for Setter - (property?)
	Member "rect"
		Security Priviledged for Setter - (property?)
	Member "setAction"
		Security Priviledged for Method, have a list of allowed Events:
Object "Lock"
	Member "action"
	Member "fields"
Object "LoginParameters"
	Member "cDIPath"
	Member "cDomain"
	Member "cMsg"
	Member "cPassword"
	Member "cPFX"
	Member "cTokenLabel"
	Member "cURL"
	Member "cUserId"
	Member "iSlotID"
	Member "oEndUserSignCert"
Object "Marker"
	Member "frame"
	Member "index"
	Member "name"
	Member "time"
Object "Markers"
	Member "get"
	Member "player"
Object "Markup"
	Member "__ALLPROPS__"
	Member "alignment"
	Member "AP"
	Member "arrowBegin"
	Member "arrowEnd"
	Member "attachIcon"
	Member "author"
	Member "borderEffectIntensity"
	Member "borderEffectStyle"
	Member "cAttachmentPath"
	Member "callout"
	Member "capOffsetH"
	Member "capOffsetV"
	Member "captionStyle"
	Member "caretSymbol"
	Member "containedPopupHeelPoint"
	Member "contents"
	Member "creationDate"
	Member "dash"
	Member "delay"
	Member "destroy"
		Security Priviledged for Method, have a list of allowed Events:
	Member "doc"
	Member "doCaption"
	Member "fillColor"
	Member "attachment"
	Member "gestures"
	Member "getProps"
	Member "getStateInModel"
	Member "hidden"
	Member "inReplyTo"
	Member "intent"
	Member "leaderExtend"
	Member "leaderLength"
	Member "leaderOffset"
	Member "lineEnding"
	Member "lock"
	Member "modDate"
	Member "name"
	Member "noteIcon"
	Member "noView"
	Member "opacity"
	Member "overlayText"
	Member "page"
	Member "point"
	Member "points"
	Member "popupHeelPoint"
	Member "popupOpen"
	Member "popupRect"
	Member "print"
	Member "quads"
	Member "readOnly"
	Member "rect"
	Member "refType"
	Member "repeat"
	Member "reviewIcon"
	Member "richContents"
	Member "richDefaults"
	Member "rotate"
	Member "seqNum"
	Member "setProps"
		Security Priviledged for Method, have a list of allowed Events:
	Member "soundIcon"
	Member "state"
	Member "stateModel"
	Member "strokeColor"
	Member "style"
	Member "subject"
	Member "textFont"
	Member "textSize"
	Member "toggleNoView"
	Member "toString"
	Member "transitionToState"
		Security Priviledged for Method, have a list of allowed Events:
	Member "type"
	Member "uiIcon"
	Member "uiType"
	Member "vertices"
	Member "width"
Object "Math"
	Member "abs"
	Member "acos"
	Member "asin"
	Member "atan"
	Member "atan2"
	Member "ceil"
	Member "cos"
	Member "exp"
	Member "floor"
	Member "log"
	Member "max"
	Member "min"
	Member "pow"
	Member "random"
	Member "round"
	Member "sin"
	Member "sqrt"
	Member "tan"
Object "MediaOffset"
	Member "frame"
	Member "marker"
	Member "time"
Object "MediaPlayer"
	Member "annot"
	Member "close"
	Member "defaultSize"
	Member "doc"
	Member "events"
	Member "hasFocus"
	Member "id"
	Member "innerRect"
	Member "isOpen"
	Member "isPlaying"
	Member "markers"
	Member "open"
	Member "outerRect"
	Member "page"
	Member "pause"
	Member "play"
	Member "privLoadMarkers"
	Member "privOpen"
	Member "seek"
	Member "setFocus"
	Member "settings"
	Member "stop"
	Member "triggerGetRect"
	Member "uiSize"
	Member "visible"
	Member "where"
Object "MediaPlayerInfoProto"
	Member "canPlay"
	Member "canUseData"
	Member "honors"
	Member "mimeTypes"
Object "MediaReject"
	Member "rendition"
Object "MediaRenditionProto"
	Member "altText"
	Member "fileName"
	Member "getPlaySettings"
Object "MediaSelection"
	Member "players"
	Member "rejects"
	Member "rendition"
	Member "selectContext"
Object "MediaSettings"
	Member "autoPlay"
	Member "baseURL"
	Member "bgColor"
	Member "bgOpacity"
	Member "data"
	Member "duration"
	Member "endAt"
	Member "floating"
	Member "layout"
	Member "monitor"
	Member "monitorType"
	Member "page"
	Member "palindrome"
	Member "players"
	Member "rate"
	Member "repeat"
	Member "showUI"
	Member "startAt"
	Member "visible"
	Member "volume"
	Member "windowType"
Object "MenuItem"
	Member "bEnabled"
	Member "bMarked"
	Member "cName"
	Member "cReturn"
	Member "oSubMenu"
Object "Monitor"
	Member "colorDepth"
	Member "isPrimary"
	Member "rect"
	Member "workRect"
Object "Monitors"
	Member "bestColor"
	Member "bestFit"
	Member "desktop"
	Member "document"
	Member "filter"
	Member "largest"
	Member "leastOverlap"
	Member "mostOverlap"
	Member "nonDocument"
	Member "primary"
	Member "secondary"
	Member "select"
	Member "tallest"
	Member "widest"
Object "Namespace"
	Member "__NOPROPS__"
Object "Net"
	Member "Discovery"
	Member "HTTP"
	Member "SOAP"
	Member "streamDecode"
	Member "streamDigest"
	Member "streamEncode"
	Member "streamFromString"
	Member "stringEncode"
	Member "stringFromStream"
	Member "Subscriptions"
	Member "wireDump"
Object "Net.Discovery"
	Member "queryServices"
	Member "resolveService"
Object "Net.HTTP"
	Member "request"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "runTaskSet"
Object "Net.SOAP"
	Member "connect"
		Security Priviledged for Method, have a list of allowed Events:
	Member "request"
		Security Priviledged for Method, have a list of allowed Events:
	Member "response"
Object "Net.Subscriptions"
	Member "addFeed"
	Member "addUI"
	Member "feeds"
	Member "getContents"
	Member "getResourceContents"
	Member "removeFeed"
	Member "update"
Object "Number"
	Member "toExponential"
	Member "toFixed"
	Member "toLocaleString"
	Member "toPrecision"
Object "nUpPageOrders"
	Member "Horizontal"
	Member "HorizontalReversed"
	Member "Vertical"
	Member "VerticalReversed"
Object "Object"
	Member "count"
	Member "hasOwnProperty"
	Member "isPrototypeOf"
	Member "parent"
	Member "propertyEnumerable"
	Member "proto"
	Member "toLocaleString"
	Member "toSource"
	Member "toString"
	Member "unwatch"
	Member "valueOf"
	Member "watch"
Object "objectFlags"
	Member "ObjImage"
	Member "ObjJPEG"
	Member "ObjJPEG2000"
	Member "ObjLineArt"
	Member "ObjLossless"
	Member "ObjLossy"
	Member "ObjOverprinting"
	Member "ObjOverprintMode"
	Member "ObjShade"
	Member "ObjText"
	Member "ObjTransparent"
Object "OCG"
	Member "constants"
	Member "getIntent"
	Member "initState"
		Security Priviledged for Setter - (property?)
	Member "locked"
		Security Priviledged for Setter - (property?)
	Member "name"
		Security Priviledged for Setter - (property?)
	Member "setAction"
	Member "setIntent"
		Security Priviledged for Method, have a list of allowed Events:
	Member "state"
	Member "toString"
	Member "valueOf"
Object "outputTypes"
	Member "EPS"
	Member "EPSPICT"
	Member "EPSTIFF"
	Member "PS"
Object "Permissions"
	Member "allowAccessibility"
	Member "allowAll"
	Member "allowChanges"
	Member "allowContentExtraction"
	Member "allowPrinting"
	Member "toString"
	Member "valueOf"
Object "PictureitObj"
	Member "__ALLPROPS__"
Object "PlayerArgs"
	Member "annot"
	Member "doc"
	Member "events"
	Member "fromUser"
	Member "mimeType"
	Member "noStockEvents"
	Member "rendition"
	Member "settings"
	Member "showAltText"
	Member "showEmptyAltText"
	Member "URL"
Object "PlayerInfo"
	Member "canPlay"
	Member "canUseData"
	Member "honors"
	Member "id"
	Member "mimeTypes"
	Member "name"
	Member "version"
Object "PlayerInfoList"
	Member "select"
Object "PlugIn"
	Member "certified"
	Member "loaded"
	Member "name"
	Member "path"
	Member "toString"
	Member "version"
Object "Preflight"
	Member "createComplianceProfile"
	Member "getNthProfile"
	Member "getNumProfiles"
	Member "getProfileByFingerPrint"
	Member "getProfileByName"
Object "PreflightAuditTrail"
	Member "preflight_executed_date"
	Member "preflight_results"
	Member "preflight_results_description"
	Member "profile_creator"
	Member "profile_creator_version"
	Member "profile_fingerprint"
	Member "profile_format_version"
	Member "profile_name"
Object "PreflightProfile"
	Member "description"
	Member "hasChecks"
	Member "hasConversion"
	Member "hasFixups"
	Member "name"
Object "PreflightResult"
	Member "numErrors"
	Member "numFixed"
	Member "numInfos"
	Member "numNotFixed"
	Member "numWarnings"
	Member "report"
Object "printContents"
	Member "doc"
	Member "docAndComments"
	Member "formFieldsOnly"
Object "printParams"
	Member "binaryOK"
	Member "bitmapDPI"
	Member "booklet"
	Member "colorOverride"
	Member "colorProfile"
	Member "constants"
	Member "downloadFarEastFonts"
	Member "DuplexType"
	Member "fileName"
	Member "printRange"
	Member "firstPage"
	Member "flags"
	Member "fontPolicy"
	Member "gradientDPI"
	Member "interactive"
	Member "lastPage"
	Member "NumCopies"
	Member "nUpAutoRotate"
	Member "nUpNumPagesH"
	Member "nUpNumPagesV"
	Member "nUpPageBorder"
	Member "nUpPageOrder"
	Member "pageHandling"
	Member "pageSubset"
	Member "printAsImage"
	Member "printContent"
	Member "printerName"
	Member "psLevel"
	Member "rasterFlags"
	Member "reversePages"
	Member "tileLabel"
	Member "tileMark"
	Member "tileOverlap"
	Member "tileScale"
	Member "transparencyLevel"
	Member "usePrinterCRD"
	Member "useT1Conversion"
Object "ProdDef"
	Member "__ALLPROPS__"
Object "ProddefCombineItem"
	Member "__ALLPROPS__"
Object "ProddefConvert"
	Member "__ALLPROPS__"
Object "ProddefConvertItem"
	Member "__ALLPROPS__"
Object "ProddefProductionSite"
	Member "__ALLPROPS__"
Object "ProddefVerify"
	Member "__ALLPROPS__"
Object "ProgressInfo"
	Member "cTaskStatus"
	Member "nCurrTask"
	Member "nNumTasks"
	Member "nPercentComplete"
	Member "setHandler"
Object "QName"
	Member "__NOPROPS__"
Object "RangeError"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "RangeError"
	Member "stack"
Object "rasterFlagValues"
	Member "allowComplexClip"
	Member "preserveOverprint"
	Member "strokesToOutline"
	Member "textToOutline"
Object "RDN"
	Member "businessCategory"
	Member "c"
	Member "cn"
	Member "countryOfCitizenship"
	Member "countryOfResidence"
	Member "dateOfBirth"
	Member "dc"
	Member "dnQualifier"
	Member "e"
	Member "gender"
	Member "generationQualifier"
	Member "givenName"
	Member "initials"
	Member "l"
	Member "name"
	Member "nameAtBirth"
	Member "o"
	Member "ou"
	Member "placeOfBirth"
	Member "postalAddress"
	Member "postalCode"
	Member "pseudonym"
	Member "serialNumber"
	Member "sn"
	Member "st"
	Member "street"
	Member "title"
	Member "toString"
	Member "valueOf"
Object "ReadStream"
	Member "read"
Object "ReferenceError"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "ReferenceError"
	Member "stack"
Object "RegExp"
	Member "compile"
	Member "exec"
	Member "test"
Object "renderingIntents"
	Member "AbsoluteColorimetric"
	Member "Any"
	Member "Document"
	Member "Perceptual"
	Member "RelativeColorimetric"
	Member "Saturation"
Object "Rendition"
	Member "altText"
	Member "doc"
	Member "fileName"
	Member "getPlaySettings"
	Member "select"
	Member "testCriteria"
	Member "type"
	Member "uiName"
Object "RenditionProto"
	Member "altText"
	Member "doc"
	Member "fileName"
	Member "getPlaySettings"
	Member "select"
	Member "testCriteria"
	Member "type"
	Member "uiName"
Object "Report"
	Member "absIndent"
	Member "assocColor"
	Member "assocOpacity"
	Member "breakPage"
	Member "color"
	Member "columns"
	Member "copyContentFromDoc"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "divide"
	Member "ignoreAnnotLayers"
	Member "indent"
	Member "joinAssocs"
	Member "mail"
	Member "open"
	Member "outdent"
	Member "print"
	Member "Report"
	Member "save"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "setFooterText"
	Member "setHeaderText"
	Member "size"
	Member "style"
	Member "writeImage"
	Member "writeText"
Object "ReqHandler"
	Member "cScriptName"
	Member "cType"
Object "Requirement"
	Member "aRH"
Object "ReviewInfo"
	Member "aComments"
	Member "bHasEverConnected"
	Member "bIsCommentRepositoryDeleted"
	Member "bIsCorrupted"
	Member "bIsEnded"
	Member "bIsSuspended"
	Member "cAccessLevel"
	Member "cDeadline"
	Member "cDeadlineUpdate"
	Member "cDeadlineWelcomeString"
	Member "cDistributionMethod"
	Member "cDriverURI"
	Member "cError"
	Member "cInitiationURL"
	Member "cInitiatorEmail"
	Member "cInitiatorName"
	Member "cInternalDeadline"
	Member "cLocalPath"
	Member "cOptionalReviewers"
	Member "cReceived"
	Member "cRequiredReviewers"
	Member "cReviewID"
	Member "cReviewURL"
	Member "cSent"
	Member "cServer"
	Member "cState"
	Member "cWorkflowsFileState"
	Member "getMetadata"
	Member "nComments"
	Member "nConnectionStatus"
	Member "nDraftComments"
	Member "nNewComments"
	Member "nNewReviewers"
	Member "nReceived"
	Member "nReviewers"
	Member "nSent"
	Member "oDeadline"
	Member "oLastUpdate"
	Member "oReviewers"
	Member "oSent"
	Member "setHandler"
	Member "setMetadata"
Object "RevocationInformation"
	Member "toString"
	Member "valueOf"
Object "RightsManagement"
	Member "captureEvent"
	Member "documentInfo"
	Member "flushEvents"
	Member "getTrackingStatus"
	Member "isOffline"
	Member "policyInfo"
	Member "serverURL"
	Member "serverVersion"
	Member "userInfo"
	Member "visitorID"
Object "RMDocument"
	Member "expiryDate"
	Member "ID"
	Member "offlineLeasePeriod"
	Member "watermarks"
Object "RMPolicy"
	Member "description"
	Member "ID"
	Member "name"
Object "RMUser"
	Member "domain"
	Member "email"
	Member "hasAlterPagesPerm"
	Member "hasChangePolicyPerm"
	Member "hasCopyPerm"
	Member "hasEditPerm"
	Member "hasFillAndSignPerm"
	Member "hasPrintHighResPerm"
	Member "hasPrintLowResPerm"
	Member "ID"
	Member "isAnonymous"
	Member "isPublisher"
	Member "name"
	Member "organization"
	Member "type"
Object "RMWatermark"
	Member "color"
	Member "colorSpace"
	Member "customText"
	Member "endPage"
	Member "fontName"
	Member "fontSize"
	Member "horizAlign"
	Member "horizOffset"
	Member "isCurrentDateEnabled"
	Member "isCustomTextEnabled"
	Member "isFixed"
	Member "isOnPrint"
	Member "isOnScreen"
	Member "isPolicyEnabled"
	Member "isUserIDEnabled"
	Member "isUserNameEnabled"
	Member "opacity"
	Member "pageSelection"
	Member "percentage"
	Member "rotation"
	Member "scale"
	Member "startPage"
	Member "type"
	Member "vertAlign"
	Member "vertOffset"
Object "Root"
	Member "acrohelp"
	Member "ADBC"
	Member "ADBCString"
	Member "AnnotsString"
	Member "app"
	Member "catalog"
	Member "Collab"
	Member "configSuite"
	Member "console"
	Member "dbg"
	Member "decodeURI"
	Member "decodeURIComponent"
	Member "DVA"
	Member "encodeURI"
	Member "encodeURIComponent"
	Member "escape"
	Member "EScriptString"
	Member "eval"
	Member "event"
	Member "exerciser"
	Member "FormsString"
	Member "FormWorkflow"
	Member "global"
	Member "identity"
	Member "Import3D"
	Member "Infinity"
	Member "isFinite"
	Member "isNaN"
	Member "isXMLName"
	Member "MultimediaString"
	Member "NaN"
	Member "Net"
	Member "parseFloat"
	Member "parseInt"
	Member "pictureit"
	Member "Preflight"
	Member "PreflightAuditTrail"
	Member "PreflightProfile"
	Member "PreflightResult"
	Member "ProdDef"
	Member "reqHandlers"
	Member "requirements"
	Member "RSS"
	Member "runAPIUnitTests"
	Member "search"
	Member "security"
	Member "shareIdentity"
	Member "SOAP"
	Member "SOAPString"
	Member "spell"
	Member "tts"
	Member "unescape"
	Member "uneval"
	Member "util"
	Member "xfa_installed"
	Member "xfa_version"
	Member "XMLData"
Object "Row"
	Member "columnArray"
Object "RSS"
	Member "addFeed"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "addUI"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "feeds"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "getContents"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getResourceContents"
	Member "removeFeed"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "update"
Object "ScreenAnnot"
	Member "__ALLPROPS__"
	Member "altText"
	Member "alwaysShowFocus"
	Member "display"
	Member "doc"
	Member "events"
	Member "extFocusRect"
	Member "hasFocus"
	Member "innerDeviceRect"
	Member "noTrigger"
	Member "outerDeviceRect"
	Member "page"
	Member "player"
	Member "rect"
	Member "setFocus"
Object "ScreenAnnotProto"
	Member "altText"
	Member "alwaysShowFocus"
	Member "display"
	Member "doc"
	Member "events"
	Member "extFocusRect"
	Member "hasFocus"
	Member "innerDeviceRect"
	Member "noTrigger"
	Member "outerDeviceRect"
	Member "page"
	Member "player"
	Member "rect"
		Security Priviledged for Setter - (property?)
	Member "setFocus"
Object "Script"
	Member "compile"
	Member "exec"
	Member "freeze"
	Member "thaw"
Object "ScriptProxy"
	Member "__ALLPROPS__"
	Member "prototype"
	Member "toSource"
	Member "toString"
Object "Search"
	Member "addIndex"
	Member "attachments"
	Member "available"
	Member "bookmarks"
	Member "docInfo"
	Member "docText"
	Member "docXMP"
	Member "getIndexForPath"
	Member "getNthIndex"
	Member "ignoreAccents"
	Member "ignoreAsianCharacterWidth"
	Member "indexes"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec

	Member "jpegExif"
	Member "legacySearch"
	Member "markup"
	Member "matchCase"
	Member "matchWholeWord"
	Member "maxDocs"
	Member "numIndexes"
	Member "objectMetadata"
	Member "proximity"
	Member "proximityRange"
	Member "query"
	Member "refine"
	Member "removeIndex"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "stem"
	Member "wordMatching"
Object "Security"
	Member "APSHandler"
	Member "chooseRecipientsDialog"
	Member "chooseSecurityPolicy"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "DigestRIPEMD160"
	Member "DigestSHA1"
	Member "DigestSHA256"
	Member "DigestSHA384"
	Member "DigestSHA512"
	Member "EncryptTargetAttachments"
	Member "EncryptTargetDocument"
	Member "exportToFile"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "getHandler"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "getSecurityPolicies"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "handlers"
	Member "importFromFile"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "importSettings"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: Field\Mouse Up

	Member "PPKLiteHandler"
	Member "StandardHandler"
	Member "toString"
	Member "validateSignaturesOnOpen"
		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "valueOf"
Object "SecurityHandler"
	Member "appearances"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "digitalIDs"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "directories"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "directoryHandlers"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "docDecrypt"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "docEncrypt"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "isLoggedIn"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "login"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "loginName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "loginPath"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "logout"
	Member "name"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "newDirectory"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "newUser"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "setPasswordTimeout"
	Member "signAuthor"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signFDF"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signInvisible"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signValidate"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "signVisible"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "stores"
	Member "toString"
	Member "uiName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "validateFDF"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "version"
Object "SecurityPolicy"
	Member "description"
	Member "handler"
	Member "name"
	Member "policyId"
	Member "target"
	Member "toString"
	Member "valueOf"
Object "SecurityPolicyOptions"
	Member "bFavorites"
	Member "cHandler"
	Member "cTarget"
Object "SecurityPolicyResults"
	Member "errorCode"
	Member "errorText"
	Member "policyApplied"
	Member "unknownRecipients"
Object "SeedValue"
	Member "certspec"
	Member "filter"
	Member "flags"
	Member "legalAttestations"
	Member "mdp"
	Member "reasons"
	Member "subFilter"
	Member "timeStampspec"
	Member "version"
Object "selection"
	Member "feed"
	Member "group"
	Member "item"
	Member "type"
Object "SharedReview"
	Member "uriNextFile"
Object "ShareIdentity"
	Member "Authenticated"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "Corporation"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "Email"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "FullName"
		Security Priviledged for Getter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init
			Event: App\Calculate

		Security Priviledged for Setter - (property?)
			Event: Batch\Exec
			Event: Console\Exec
			Event: App\Init

	Member "Title"
Object "SigInfo"
	Member "appearance"
	Member "appRightsAnnots"
	Member "appRightsDocument"
	Member "appRightsEF"
	Member "appRightsForm"
	Member "appRightsSignature"
	Member "buildInfo"
	Member "byteRange"
	Member "certificates"
	Member "contactInfo"
	Member "date"
	Member "dateTrusted"
	Member "digestMethod"
	Member "docValidity"
	Member "handlerName"
	Member "handlerUIName"
	Member "handlerUserName"
	Member "idPrivValidity"
	Member "idValidity"
	Member "location"
	Member "mdp"
	Member "name"
	Member "numFieldsAltered"
	Member "numFieldsFilledIn"
	Member "numPagesAltered"
	Member "numRevisions"
	Member "objValidity"
	Member "password"
	Member "reason"
	Member "revInfo"
	Member "revision"
	Member "sigValue"
	Member "status"
	Member "statusText"
	Member "subFilter"
	Member "timeStamp"
	Member "trustFlags"
	Member "verifyDate"
	Member "verifyHandlerName"
	Member "verifyHandlerUIName"
	Member "NumberOfChains"
	Member "NumberOfTrustedChains"
	Member "LTVStatus"
	Member "LTVStatusText"
	Member "ExpirationTime"
Object "SignatureModification"
	Member "annotsCreated"
	Member "annotsDeleted"
	Member "annotsModified"
	Member "formFieldsCreated"
	Member "formFieldsDeleted"
	Member "formFieldsFilledIn"
	Member "formFieldsModified"
	Member "numPagesCreated"
	Member "numPagesDeleted"
	Member "numPagesModified"
	Member "spawnedPagesCreated"
	Member "spawnedPagesDeleted"
	Member "spawnedPagesModified"
Object "SignatureParameters"
	Member "bAltSecHdlr"
	Member "oSecHdlr"
Object "SOAP"
	Member "connect"
		Security Priviledged for Method, have a list of allowed Events:
	Member "queryServices"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "request"
		Security Priviledged for Method, have a list of allowed Events:
	Member "resolveService"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "response"
		Security Priviledged for Method, have a list of allowed Events:
	Member "streamDecode"
	Member "streamDigest"
	Member "streamEncode"
	Member "streamFromString"
	Member "stringEncode"
	Member "stringFromStream"
	Member "stripNS"
	Member "wireDump"
Object "SOAPService"
	Member "__NOPROPS__"
Object "Sound"
	Member "name"
	Member "pause"
	Member "play"
	Member "stop"
	Member "toString"
	Member "valueOf"
Object "spaceFlags"
	Member "AlternateSpace"
	Member "BaseSpace"
	Member "CalibratedSpace"
	Member "CMYKSpace"
	Member "DeviceNSpace"
	Member "DeviceSpace"
	Member "GraySpace"
	Member "IndexedSpace"
	Member "LabSpace"
	Member "NChannelSpace"
	Member "RGBSpace"
	Member "SeparationSpace"
Object "Span"
	Member "alignment"
	Member "fontFamily"
	Member "fontStretch"
	Member "fontStyle"
	Member "fontWeight"
	Member "strikethrough"
	Member "subscript"
	Member "superscript"
	Member "text"
	Member "textColor"
	Member "textSize"
	Member "underline"
Object "Spell"
	Member "addDictionary"
	Member "addWord"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "available"
	Member "check"
	Member "checkText"
	Member "checkWord"
	Member "customDictionaryClose"
	Member "customDictionaryCreate"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "customDictionaryDelete"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "customDictionaryExport"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "customDictionaryOpen"
	Member "dictionaryNames"
	Member "dictionaryOrder"
	Member "domainNames"
	Member "ignoreAll"
	Member "ignoredWords"
	Member "languageOrder"
	Member "languages"
	Member "removeDictionary"
	Member "removeWord"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "userWords"
Object "Statement"
	Member "columnCount"
	Member "cursorName"
	Member "execute"
	Member "getColumn"
	Member "getColumnArray"
	Member "getRow"
	Member "nextRow"
	Member "rowCount"
Object "States"
	Member "cUIName"
	Member "oIcon"
Object "states"
	Member "off"
	Member "on"
Object "Stream"
	Member "read"
	Member "write"
Object "String"
	Member "anchor"
	Member "big"
	Member "blink"
	Member "bold"
	Member "charAt"
	Member "charCodeAt"
	Member "concat"
	Member "fixed"
	Member "fontcolor"
	Member "fontsize"
	Member "indexOf"
	Member "italics"
	Member "lastIndexOf"
	Member "link"
	Member "localeCompare"
	Member "match"
	Member "quote"
	Member "replace"
	Member "search"
	Member "slice"
	Member "small"
	Member "split"
	Member "strike"
	Member "sub"
	Member "substr"
	Member "substring"
	Member "sup"
	Member "toLocaleLowerCase"
	Member "toLocaleUpperCase"
	Member "toLowerCase"
	Member "toUpperCase"
Object "stringGetterObj"
	Member "__ALLPROPS__"
Object "subsets"
	Member "all"
	Member "even"
	Member "odd"
Object "SyntaxError"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "stack"
	Member "SyntaxError"
Object "TableInfo"
	Member "description"
	Member "name"
Object "Template"
	Member "hidden"
		Security Priviledged for Setter - (property?)
	Member "name"
	Member "spawn"
		Security Priviledged for Method, have a list of allowed Events:
	Member "toString"
	Member "valueOf"
Object "Thermometer"
	Member "begin"
	Member "cancelled"
	Member "duration"
	Member "end"
	Member "text"
	Member "toString"
	Member "value"
Object "tileMarks"
	Member "east"
	Member "none"
	Member "west"
Object "TimeOut"
	Member "__NOPROPS__"
Object "treeItem"
	Member "cName"
	Member "oChildren"
	Member "toString"
Object "TTS"
	Member "available"
	Member "characterScale"
	Member "getNthSpeakerName"
	Member "letter"
	Member "numSpeakers"
	Member "pause"
	Member "pitch"
	Member "punctuations"
	Member "qSilence"
	Member "qSound"
	Member "qText"
	Member "qTone"
	Member "reset"
	Member "resume"
	Member "soundCues"
	Member "speaker"
	Member "speechCues"
	Member "speechRate"
	Member "stop"
	Member "talk"
	Member "volume"
Object "TypeError"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "stack"
	Member "TypeError"
Object "UBRights"
	Member "mode"
	Member "rights"
	Member "toString"
	Member "valueOf"
Object "UIDriverObject"
	Member "canInitiateWorkflow"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "driverURL"
	Member "getInitiatorConfig"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getInitiatorSource"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "getWorkspaceCreator"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

	Member "initiatorAddServer"
	Member "initiatorDefaultName"
	Member "initiatorDescription"
	Member "initiatorName"
	Member "isDocCenterWorkflow"
		Security Priviledged for Method, have a list of allowed Events:
			Event: Batch\Exec
			Event: Console\Exec

Object "UnsupportedOptions"
	Member "__NOPROPS__"
Object "URIError"
	Member "extMessage"
	Member "fileName"
	Member "lineNumber"
	Member "message"
	Member "name"
	Member "stack"
	Member "URIError"
Object "Usage"
	Member "endUserEncryption"
	Member "endUserSigning"
Object "usages"
	Member "auto"
	Member "noUse"
	Member "use"
Object "UserEntity"
	Member "certificates"
	Member "defaultEncryptCert"
	Member "firstName"
	Member "fullName"
	Member "lastName"
Object "Util"
	Member "byteToChar"
	Member "charToByte"
	Member "crackURL"
	Member "fixOldString"
	Member "iconStreamFromIcon"
	Member "printd"
	Member "printf"
	Member "printx"
	Member "readFileIntoStream"
	Member "scand"
	Member "spansToXML"
	Member "streamFromString"
	Member "StringFromStream"
	Member "stringFromStream"
	Member "xmlToSpans"
Object "ViewState"
	Member "toSource"
Object "XFAField"
	Member "__ALLPROPS__"
Object "XFAObject"
	Member "__ALLPROPS__"
Object "XFAScriptObject"
	Member "__ALLPROPS__"
Object "XML"
	Member "addNamespace"
	Member "appendChild"
	Member "attribute"
	Member "attributes"
	Member "child"
	Member "childIndex"
	Member "children"
	Member "comments"
	Member "contains"
	Member "copy"
	Member "defaultSettings"
	Member "descendants"
	Member "elements"
	Member "hasComplexContent"
	Member "hasOwnProperty"
	Member "hasSimpleContent"
	Member "inScopeNamespaces"
	Member "insertChildAfter"
	Member "insertChildBefore"
	Member "length"
	Member "localName"
	Member "name"
	Member "namespace"
	Member "namespaceDeclarations"
	Member "nodeKind"
	Member "normalize"
	Member "parent"
	Member "prependChild"
	Member "processingInstructions"
	Member "propertyIsEnumerable"
	Member "removeNamespace"
	Member "replace"
	Member "setChildren"
	Member "setLocalName"
	Member "setName"
	Member "setNamespace"
	Member "setSettings"
	Member "settings"
	Member "text"
	Member "toXMLString"
Object "XMLData"
	Member "applyXPath"
	Member "parse"
{% endhighlight %}