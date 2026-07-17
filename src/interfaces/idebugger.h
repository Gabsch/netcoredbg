// Copyright (c) 2017 Samsung Electronics Co., LTD
// Distributed under the MIT License.
// See the LICENSE file in the project root for more information.

#pragma once

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <memory>
#include "interfaces/types.h"
#include "utils/string_view.h"
#include "utils/streams.h"

namespace netcoredbg
{
using Utility::string_view;

class IDebugger
{
public:
    enum class RewindSafety
    {
        Safe,
        Unsafe,
        Unknown
    };

    struct RewindFrameIdentity
    {
        std::string stopId;
        ThreadId threadId;
        FrameId frameId;
        std::string moduleMvid;
        uint32_t methodToken = 0;
        ULONG32 functionVersion = 0;
        ULONG32 ilOffset = 0;
    };

    struct RewindTarget
    {
        RewindSafety safety = RewindSafety::Unknown;
        std::string reasonCode;
        std::string reason;
        HRESULT canSetIpHResult = static_cast<HRESULT>(0x80004005u);
        RewindFrameIdentity frame;
        std::string targetId;
        Source source;
        int requestedLine = 0;
        int resolvedLine = 0;
        int resolvedColumn = 0;
        ULONG32 targetIlOffset = 0;
        int expiresInMs = 0;
    };

    struct InstructionPointerResult
    {
        bool moved = false;
        bool handlesInvalidated = false;
        std::string reasonCode;
        std::string reason;
        HRESULT canSetIpHResult = static_cast<HRESULT>(0x80004005u);
        HRESULT setIpHResult = static_cast<HRESULT>(0x80004005u);
        RewindFrameIdentity previousFrame;
        RewindFrameIdentity currentFrame;
        StackFrame stoppedFrame;
        std::vector<std::string> warnings;
    };

    struct HotReloadMethodGeneration
    {
        uint32_t methodToken = 0;
        ULONG32 previousGeneration = 0;
        ULONG32 appliedGeneration = 0;
    };

    struct FrameGenerationEvidence
    {
        RewindFrameIdentity frame;
        ULONG32 latestGeneration = 0;
        std::string invocationId;
    };

    struct ActiveFrameRemapTarget : RewindTarget
    {
        ULONG32 appliedGeneration = 0;
        std::string invocationId;
    };

    enum StepType
    {
        STEP_IN = 0,
        STEP_OVER,
        STEP_OUT
    };

    enum DisconnectAction
    {
        DisconnectDefault, // Attach -> Detach, Launch -> Terminate
        DisconnectTerminate,
        DisconnectDetach
    };

    // This is lightweight structure which carry breakpoint information.
    struct BreakpointInfo
    {
        unsigned    id;
        bool        resolved;
        bool        enabled;
        unsigned    hit_count;
        std::string condition; // not empty for conditional breakpoints
        std::string name;      // file name or function name, depending on type.
        int         line;      // first line, 0 for function breakpoint
        int         last_line;
        std::string module;    // module name
        std::string funcsig;   // might be non-empty for function breakpoints

        bool operator<(const BreakpointInfo& other) const { return id < other.id; }
        bool operator==(const BreakpointInfo& other) const { return id == other.id; }
    };

    enum class AsyncResult
    {
        Canceled,   // function canceled due to debugger interruption
        Error,      // IO error
        Eof         // EOF reached
    };
    virtual IDebugger::AsyncResult ProcessStdin(InStream &) { return IDebugger::AsyncResult::Eof; }


    virtual ~IDebugger() {}
    virtual bool IsJustMyCode() const = 0;
    virtual void SetJustMyCode(bool enable) = 0;
    virtual bool IsStepFiltering() const = 0;
    virtual void SetStepFiltering(bool enable) = 0;
    virtual bool IsHotReload() const = 0;
    virtual bool IsAttachSession() const = 0;
    virtual HRESULT SetHotReload(bool enable) = 0;
#ifdef INTEROP_DEBUGGING
    virtual void SetInteropDebugging(bool enable) = 0;
#endif
    virtual HRESULT Initialize() = 0;
    virtual HRESULT Attach(int pid) = 0;
    virtual HRESULT Launch(const std::string &fileExec, const std::vector<std::string> &execArgs, const std::map<std::string, std::string> &env,
        const std::string &cwd, bool stopAtEntry = false) = 0;
    virtual HRESULT ConfigurationDone() = 0;
    virtual HRESULT Disconnect(DisconnectAction action = DisconnectDefault) = 0;
    virtual ThreadId GetLastStoppedThreadId() = 0;
    virtual HRESULT Continue(ThreadId threadId) = 0;
    virtual HRESULT Pause(ThreadId lastStoppedThread, EventFormat eventFormat) = 0;
    virtual HRESULT GetThreads(std::vector<Thread> &threads, bool withNativeThreads = false) = 0;
    virtual HRESULT UpdateLineBreakpoint(int id, int linenum, Breakpoint &breakpoint) = 0;
    virtual HRESULT SetLineBreakpoints(const std::string& filename, const std::vector<LineBreakpoint> &lineBreakpoints, std::vector<Breakpoint> &breakpoints) = 0;
    virtual HRESULT SetFuncBreakpoints(const std::vector<FuncBreakpoint> &funcBreakpoints, std::vector<Breakpoint> &breakpoints) = 0;
    virtual HRESULT SetExceptionBreakpoints(const std::vector<ExceptionBreakpoint> &exceptionBreakpoints, std::vector<Breakpoint> &breakpoints) = 0;
    virtual HRESULT BreakpointActivate(int id, bool act) = 0;
    virtual void EnumerateBreakpoints(std::function<bool (const BreakpointInfo&)>&& callback) = 0;
    virtual HRESULT AllBreakpointsActivate(bool act) = 0;
    virtual HRESULT GetStackTrace(ThreadId threadId, FrameLevel startFrame, unsigned maxFrames, std::vector<StackFrame> &stackFrames, int &totalFrames, bool hotReloadAwareCaller = false) = 0;
    virtual HRESULT StepCommand(ThreadId threadId, StepType stepType) = 0;
    virtual HRESULT GetScopes(FrameId frameId, std::vector<Scope> &scopes) = 0;
    virtual HRESULT GetVariables(uint32_t variablesReference, VariablesFilter filter, int start, int count, std::vector<Variable> &variables) = 0;
    virtual int GetNamedVariables(uint32_t variablesReference) = 0;
    virtual HRESULT Evaluate(FrameId frameId, const std::string &expression, Variable &variable, std::string &output) = 0;
    virtual void CancelEvalRunning() = 0;
    virtual HRESULT SetVariable(const std::string &name, const std::string &value, uint32_t ref, std::string &output) = 0;
    virtual HRESULT SetExpression(FrameId frameId, const std::string &expression, int evalFlags, const std::string &value, std::string &output) = 0;
    virtual HRESULT ResolveRewindTarget(ThreadId threadId, FrameId frameId, const std::string &sourceFile, int line, RewindTarget &target) = 0;
    virtual HRESULT SetInstructionPointer(const std::string &targetId, const RewindFrameIdentity &expectedFrame, InstructionPointerResult &result) = 0;
    virtual HRESULT InspectFrameGeneration(ThreadId threadId, FrameId frameId, FrameGenerationEvidence &evidence) = 0;
    virtual HRESULT ResolveActiveFrameRemapTarget(ThreadId threadId, FrameId frameId, const std::string &sourceFile, int line,
                                                   const std::string &moduleMvid, uint32_t methodToken,
                                                   ULONG32 appliedGeneration, ActiveFrameRemapTarget &target) = 0;
    virtual HRESULT ArmActiveFrameRemap(const std::string &targetId, const RewindFrameIdentity &expectedFrame) = 0;
    virtual HRESULT GetExceptionInfo(ThreadId threadId, ExceptionInfo &exceptionInfo) = 0;
    virtual HRESULT GetSourceFile(const std::string &sourcePath, char** fileBuf, int* fileLen) = 0;
    virtual void FreeUnmanaged(PVOID mem) = 0;
    virtual HRESULT HotReloadApplyDeltas(const std::string &dllFileName, const std::string &moduleMvid,
                                         const std::vector<uint32_t> &updatedMethodTokens,
                                         const std::string &deltaMD, const std::string &deltaIL,
                                         const std::string &deltaPDB, const std::string &lineUpdates,
                                         std::vector<HotReloadMethodGeneration> &methodGenerations,
                                         std::string &failureStage) = 0;
    virtual HRESULT HotReloadApplyDeltas(const std::string &dllFileName, const std::string &deltaMD, const std::string &deltaIL,
                                         const std::string &deltaPDB, const std::string &lineUpdates) = 0;
    typedef std::function<void(const char *)> SearchCallback;
    virtual void FindFileNames(string_view pattern, unsigned limit, SearchCallback) = 0;
    virtual void FindFunctions(string_view pattern, unsigned limit, SearchCallback) = 0;
    virtual void FindVariables(ThreadId, FrameLevel, string_view, unsigned limit, SearchCallback) = 0;
};

} // namespace netcoredbg
