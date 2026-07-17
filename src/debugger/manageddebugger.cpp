// Copyright (c) 2017 Samsung Electronics Co., LTD
// Distributed under the MIT License.
// See the LICENSE file in the project root for more information.

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include <sstream>
#include <algorithm>
#include <mutex>
#include <memory>
#include <chrono>
#include <stdexcept>
#include <vector>
#include <map>
#include <fstream>
#include <iomanip>
#include <random>
#include <unordered_set>

#include <sys/types.h>
#include <sys/stat.h>
#include "interfaces/iprotocol.h"
#include "debugger/threads.h"
#include "debugger/frames.h"
#include "debugger/evalhelpers.h"
#include "debugger/evalstackmachine.h"
#include "debugger/evaluator.h"
#include "debugger/evalwaiter.h"
#include "debugger/variables.h"
#include "debugger/breakpoint_break.h"
#include "debugger/breakpoint_entry.h"
#include "debugger/breakpoints_exception.h"
#include "debugger/breakpoints_func.h"
#include "debugger/breakpoints_line.h"
#include "debugger/breakpoint_hotreload.h"
#include "debugger/breakpoint_interop_rendezvous.h"
#include "debugger/breakpoints_interop.h"
#include "debugger/breakpoints_interop_line.h"
#include "debugger/breakpoints_interop_func.h"
#include "debugger/breakpoints.h"
#include "debugger/hotreloadhelpers.h"
#include "debugger/manageddebugger.h"
#include "debugger/managedcallback.h"
#include "debugger/callbacksqueue.h"
#include "debugger/stepper_simple.h"
#include "debugger/stepper_async.h"
#include "debugger/steppers.h"
#include "managed/interop.h"
#include "metadata/interop_libraries.h"
#include "utils/utf.h"
#include "utils/dynlibs.h"
#include "metadata/modules.h"
#include "metadata/typeprinter.h"
#include "utils/logger.h"
#include "debugger/waitpid.h"
#include "utils/iosystem.h"

#ifdef INTEROP_DEBUGGING
#include "elf++.h"
#include "dwarf++.h"
#include "debugger/sigaction.h"
#endif // INTEROP_DEBUGGING

#include "palclr.h"

namespace netcoredbg
{

#ifdef FEATURE_PAL

// as alternative, libuuid should be linked...
// the problem is, that in CoreClr > 3.x, in pal/inc/rt/rpc.h,
// MIDL_INTERFACE uses DECLSPEC_UUID, which has empty definition.
extern "C" const IID IID_IUnknown = { 0x00000000, 0x0000, 0x0000, {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46 }};

#endif // FEATURE_PAL

namespace
{
    const auto startupWaitTimeout = std::chrono::milliseconds(5000);
    const auto rewindTargetLifetime = std::chrono::seconds(30);
    constexpr std::size_t maxRewindTargets = 64;

    const std::string envDOTNET_STARTUP_HOOKS = "DOTNET_STARTUP_HOOKS";
#ifdef FEATURE_PAL
    const char delimiterDOTNET_STARTUP_HOOKS = ':';
#else  // FEATURE_PAL
    const char delimiterDOTNET_STARTUP_HOOKS = ';';
#endif // FEATURE_PAL

#ifdef INTEROP_DEBUGGING
    const std::string envNCDB_INTEROP_DEBUGGING = "NCDB_INTEROP_DEBUGGING";
#endif // INTEROP_DEBUGGING

    std::string NewRewindTargetId()
    {
        std::random_device random;
        std::ostringstream stream;
        stream << "rewind_" << std::hex << std::setfill('0');
        for (int i = 0; i < 4; ++i)
            stream << std::setw(8) << random();
        return stream.str();
    }

    bool FrameIdentityEquals(const IDebugger::RewindFrameIdentity &left, const IDebugger::RewindFrameIdentity &right)
    {
        return left.stopId == right.stopId &&
            int(left.threadId) == int(right.threadId) &&
            int(left.frameId) == int(right.frameId) &&
            left.moduleMvid == right.moduleMvid &&
            left.methodToken == right.methodToken &&
            left.functionVersion == right.functionVersion &&
            left.ilOffset == right.ilOffset;
    }

    bool HasRange(const std::vector<unsigned char> &bytes, std::size_t offset, std::size_t length)
    {
        return offset <= bytes.size() && length <= bytes.size() - offset;
    }

    bool ReadUInt16(const std::vector<unsigned char> &bytes, std::size_t offset, uint16_t &value)
    {
        if (!HasRange(bytes, offset, 2))
            return false;
        value = uint16_t(bytes[offset]) | (uint16_t(bytes[offset + 1]) << 8);
        return true;
    }

    bool ReadUInt32(const std::vector<unsigned char> &bytes, std::size_t offset, uint32_t &value)
    {
        if (!HasRange(bytes, offset, 4))
            return false;
        value = uint32_t(bytes[offset]) |
            (uint32_t(bytes[offset + 1]) << 8) |
            (uint32_t(bytes[offset + 2]) << 16) |
            (uint32_t(bytes[offset + 3]) << 24);
        return true;
    }

    std::size_t Align4(std::size_t value)
    {
        return (value + 3u) & ~std::size_t(3u);
    }

    bool TryMapRvaToFileOffset(
        const std::vector<unsigned char> &bytes,
        uint32_t rva,
        std::size_t &fileOffset)
    {
        uint32_t peOffset = 0;
        if (!HasRange(bytes, 0, 0x40) ||
            bytes[0] != 'M' ||
            bytes[1] != 'Z' ||
            !ReadUInt32(bytes, 0x3c, peOffset) ||
            !HasRange(bytes, peOffset, 24) ||
            bytes[peOffset] != 'P' ||
            bytes[peOffset + 1] != 'E' ||
            bytes[peOffset + 2] != 0 ||
            bytes[peOffset + 3] != 0)
        {
            return false;
        }

        const std::size_t fileHeader = std::size_t(peOffset) + 4;
        uint16_t sectionCount = 0;
        uint16_t optionalHeaderSize = 0;
        if (!ReadUInt16(bytes, fileHeader + 2, sectionCount) ||
            !ReadUInt16(bytes, fileHeader + 16, optionalHeaderSize))
        {
            return false;
        }

        const std::size_t sectionTable = fileHeader + 20 + optionalHeaderSize;
        for (uint16_t index = 0; index < sectionCount; ++index)
        {
            const std::size_t section = sectionTable + std::size_t(index) * 40;
            uint32_t virtualSize = 0;
            uint32_t virtualAddress = 0;
            uint32_t rawSize = 0;
            uint32_t rawOffset = 0;
            if (!ReadUInt32(bytes, section + 8, virtualSize) ||
                !ReadUInt32(bytes, section + 12, virtualAddress) ||
                !ReadUInt32(bytes, section + 16, rawSize) ||
                !ReadUInt32(bytes, section + 20, rawOffset))
            {
                return false;
            }

            const uint64_t mappedSize = std::max<uint32_t>(virtualSize, rawSize);
            if (uint64_t(rva) < virtualAddress ||
                uint64_t(rva) >= uint64_t(virtualAddress) + mappedSize)
            {
                continue;
            }

            const uint64_t resolved = uint64_t(rawOffset) + (uint64_t(rva) - virtualAddress);
            if (resolved >= bytes.size())
                return false;
            fileOffset = std::size_t(resolved);
            return true;
        }

        return false;
    }

    bool ParseSmallExceptionClause(
        const std::vector<unsigned char> &bytes,
        std::size_t offset,
        CorDebugEHClause &clause)
    {
        uint16_t flags = 0;
        uint16_t tryOffset = 0;
        uint16_t handlerOffset = 0;
        uint32_t classTokenOrFilterOffset = 0;
        if (!ReadUInt16(bytes, offset, flags) ||
            !ReadUInt16(bytes, offset + 2, tryOffset) ||
            !ReadUInt16(bytes, offset + 5, handlerOffset) ||
            !ReadUInt32(bytes, offset + 8, classTokenOrFilterOffset))
        {
            return false;
        }

        clause = {};
        clause.Flags = flags;
        clause.TryOffset = tryOffset;
        clause.TryLength = bytes[offset + 4];
        clause.HandlerOffset = handlerOffset;
        clause.HandlerLength = bytes[offset + 7];
        if ((flags & 0x00000001u) != 0)
            clause.FilterOffset = classTokenOrFilterOffset;
        else
            clause.ClassToken = classTokenOrFilterOffset;
        return true;
    }

    bool ParseFatExceptionClause(
        const std::vector<unsigned char> &bytes,
        std::size_t offset,
        CorDebugEHClause &clause)
    {
        uint32_t classTokenOrFilterOffset = 0;
        clause = {};
        if (!ReadUInt32(bytes, offset, clause.Flags) ||
            !ReadUInt32(bytes, offset + 4, clause.TryOffset) ||
            !ReadUInt32(bytes, offset + 8, clause.TryLength) ||
            !ReadUInt32(bytes, offset + 12, clause.HandlerOffset) ||
            !ReadUInt32(bytes, offset + 16, clause.HandlerLength) ||
            !ReadUInt32(bytes, offset + 20, classTokenOrFilterOffset))
        {
            return false;
        }

        if ((clause.Flags & 0x00000001u) != 0)
            clause.FilterOffset = classTokenOrFilterOffset;
        else
            clause.ClassToken = classTokenOrFilterOffset;
        return true;
    }

    HRESULT ReadExceptionClausesFromModule(
        ICorDebugModule *module,
        mdMethodDef methodToken,
        std::vector<CorDebugEHClause> &clauses)
    {
        ToRelease<IUnknown> metadataUnknown;
        HRESULT Status = module->GetMetaDataInterface(IID_IMetaDataImport, &metadataUnknown);
        if (FAILED(Status))
            return Status;

        ToRelease<IMetaDataImport> metadata;
        Status = metadataUnknown->QueryInterface(IID_IMetaDataImport, (LPVOID*) &metadata);
        if (FAILED(Status))
            return Status;

        ULONG methodRva = 0;
        DWORD implementationFlags = 0;
        Status = metadata->GetRVA(methodToken, &methodRva, &implementationFlags);
        if (FAILED(Status) || methodRva == 0)
            return FAILED(Status) ? Status : E_FAIL;

        const std::string modulePath = GetModuleFileName(module);
        std::ifstream stream(modulePath, std::ios::binary | std::ios::ate);
        if (!stream)
            return E_FAIL;

        const std::streamoff length = stream.tellg();
        if (length <= 0)
            return E_FAIL;
        stream.seekg(0, std::ios::beg);
        std::vector<unsigned char> bytes(static_cast<std::size_t>(length), 0);
        if (!stream.read(reinterpret_cast<char*>(bytes.data()), length))
            return E_FAIL;

        std::size_t methodOffset = 0;
        if (!TryMapRvaToFileOffset(bytes, methodRva, methodOffset) ||
            !HasRange(bytes, methodOffset, 1))
        {
            return E_FAIL;
        }

        constexpr unsigned char TinyFormat = 0x02;
        constexpr unsigned char FatFormat = 0x03;
        constexpr uint16_t MoreSections = 0x0008;
        const unsigned char format = bytes[methodOffset] & 0x03;
        if (format == TinyFormat)
            return S_OK;
        if (format != FatFormat)
            return E_FAIL;

        uint16_t flagsAndSize = 0;
        uint32_t codeSize = 0;
        if (!ReadUInt16(bytes, methodOffset, flagsAndSize) ||
            !ReadUInt32(bytes, methodOffset + 4, codeSize))
        {
            return E_FAIL;
        }

        const std::size_t headerSize = std::size_t((flagsAndSize >> 12) & 0x0f) * 4;
        if (headerSize < 12 || !HasRange(bytes, methodOffset, headerSize + codeSize))
            return E_FAIL;
        if ((flagsAndSize & MoreSections) == 0)
            return S_OK;

        std::size_t sectionOffset = Align4(methodOffset + headerSize + codeSize);
        bool moreSections = true;
        while (moreSections)
        {
            if (!HasRange(bytes, sectionOffset, 4))
                return E_FAIL;

            const unsigned char kind = bytes[sectionOffset];
            const bool fatSection = (kind & 0x40) != 0;
            moreSections = (kind & 0x80) != 0;
            const unsigned char sectionKind = kind & 0x3f;
            const uint32_t dataSize = fatSection
                ? uint32_t(bytes[sectionOffset + 1]) |
                    (uint32_t(bytes[sectionOffset + 2]) << 8) |
                    (uint32_t(bytes[sectionOffset + 3]) << 16)
                : uint32_t(bytes[sectionOffset + 1]);
            if (dataSize < 4 || !HasRange(bytes, sectionOffset, dataSize))
                return E_FAIL;

            if (sectionKind == 0x01)
            {
                const std::size_t clauseSize = fatSection ? 24 : 12;
                if ((dataSize - 4) % clauseSize != 0)
                    return E_FAIL;

                const std::size_t clauseCount = (dataSize - 4) / clauseSize;
                for (std::size_t index = 0; index < clauseCount; ++index)
                {
                    CorDebugEHClause clause;
                    const std::size_t clauseOffset = sectionOffset + 4 + index * clauseSize;
                    const bool parsed = fatSection
                        ? ParseFatExceptionClause(bytes, clauseOffset, clause)
                        : ParseSmallExceptionClause(bytes, clauseOffset, clause);
                    if (!parsed)
                        return E_FAIL;
                    clauses.push_back(clause);
                }
            }

            sectionOffset = Align4(sectionOffset + dataSize);
        }

        return S_OK;
    }

    int GetSystemEnvironmentAsMap(std::map<std::string, std::string>& outMap)
    {
        char*const*const pEnv = GetSystemEnvironment();

        if (pEnv == nullptr)
            return -1;

        int counter = 0;
        while (pEnv[counter] != nullptr)
        {
            const std::string env = pEnv[counter];
            size_t pos = env.find_first_of("=");
            if (pos != std::string::npos && pos != 0)
                outMap.emplace(env.substr(0, pos), env.substr(pos+1));

            ++counter;
        }

        return 0;
    }
}

// Caller must care about m_debugProcessRWLock.
HRESULT ManagedDebuggerBase::CheckDebugProcess()
{
    if (!m_iCorProcess)
        return E_FAIL;

    // We might have case, when process was exited/detached, but m_iCorProcess still not free and hold invalid object.
    // Note, we can't hold this lock, since this could deadlock execution at ICorDebugManagedCallback::ExitProcess call.
    std::unique_lock<std::mutex> lockAttachedMutex(m_processAttachedMutex);
    if (m_processAttachedState == ProcessAttachedState::Unattached)
        return E_FAIL;
    lockAttachedMutex.unlock();

    return S_OK;
}

bool ManagedDebuggerBase::HaveDebugProcess()
{
    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    return SUCCEEDED(CheckDebugProcess());
}

void ManagedDebuggerBase::NotifyProcessCreated()
{
    std::unique_lock<std::mutex> lock(m_processAttachedMutex);
    m_processAttachedState = ProcessAttachedState::Attached;
    lock.unlock();
    m_processAttachedCV.notify_one();
}

void ManagedDebuggerBase::NotifyProcessExited()
{
    InvalidateRewindTargets();
    InvalidateActiveFrameRemapTargets();
    std::unique_lock<std::mutex> lock(m_processAttachedMutex);
    m_processAttachedState = ProcessAttachedState::Unattached;
    lock.unlock();
    m_processAttachedCV.notify_all();
}

// Caller must care about m_debugProcessRWLock.
void ManagedDebuggerBase::DisableAllBreakpointsAndSteppers()
{
    m_uniqueSteppers->DisableAllSteppers(m_iCorProcess); // Async stepper could have breakpoints active, disable them first.
    m_sharedBreakpoints->DeleteAllManaged();
    m_sharedBreakpoints->DisableAllManaged(m_iCorProcess); // Last one, disable all breakpoints on all domains, even if we don't hold them.
}

void ManagedDebuggerBase::SetLastStoppedThread(ICorDebugThread *pThread)
{
    SetLastStoppedThreadId(getThreadId(pThread));
}

void ManagedDebuggerBase::SetLastStoppedThreadId(ThreadId threadId)
{
    {
        std::lock_guard<std::mutex> lock(m_lastStoppedMutex);
        m_lastStoppedThreadId = threadId;
        ++m_stoppedEpoch;
    }
    InvalidateRewindTargets();
    InvalidateActiveFrameRemapTargets();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);

    m_sharedBreakpoints->SetLastStoppedIlOffset(m_iCorProcess, threadId);
}

void ManagedDebuggerBase::InvalidateLastStoppedThreadId()
{
    SetLastStoppedThreadId(ThreadId::AllThreads);
}

void ManagedDebuggerBase::InvalidateRewindTargets()
{
    std::lock_guard<std::mutex> lock(m_rewindTargetsMutex);
    m_rewindTargets.clear();
}

void ManagedDebuggerBase::InvalidateActiveFrameRemapTargets()
{
    std::lock_guard<std::mutex> lock(m_activeFrameRemapMutex);
    m_activeFrameRemapTargets.clear();
    m_armedActiveFrameRemapId.clear();
    m_haveActiveFrameRemapEvent = false;
}

std::string ManagedDebuggerBase::CurrentStopId()
{
    std::lock_guard<std::mutex> lock(m_lastStoppedMutex);
    return "stop_" + std::to_string(m_stoppedEpoch);
}

ThreadId ManagedDebugger::GetLastStoppedThreadId()
{
    LogFuncEntry();

    std::lock_guard<std::mutex> lock(m_lastStoppedMutex);
    return m_lastStoppedThreadId;
}

ManagedDebuggerBase::ManagedDebuggerBase(IProtocol *pProtocol_) :
    m_processAttachedState(ProcessAttachedState::Unattached),
    m_lastStoppedThreadId(ThreadId::AllThreads),
    m_stoppedEpoch(0),
    m_startMethod(StartNone),
    m_isConfigurationDone(false),
    pProtocol(pProtocol_),
    m_sharedThreads(new Threads),
    m_sharedModules(new Modules),
    m_sharedEvalWaiter(new EvalWaiter),
    m_sharedEvalHelpers(new EvalHelpers(m_sharedModules, m_sharedEvalWaiter)),
    m_sharedEvalStackMachine(new EvalStackMachine),
    m_sharedEvaluator(new Evaluator(m_sharedModules, m_sharedEvalHelpers, m_sharedEvalStackMachine)),
    m_sharedVariables(new Variables(m_sharedEvalHelpers, m_sharedEvaluator, m_sharedEvalStackMachine)),
    m_uniqueSteppers(new Steppers(m_sharedModules, m_sharedEvalHelpers)),
    m_sharedBreakpoints(new Breakpoints(m_sharedModules, m_sharedEvaluator, m_sharedEvalHelpers, m_sharedVariables)),
    m_sharedCallbacksQueue(nullptr),
    m_uniqueManagedCallback(nullptr),
#ifdef INTEROP_DEBUGGING
    m_sharedInteropDebugger(new InteropDebugging::InteropDebugger(pProtocol, m_sharedBreakpoints, m_sharedEvalWaiter)),
#endif // INTEROP_DEBUGGING
    m_justMyCode(true),
    m_stepFiltering(true),
    m_hotReload(false),
    m_interopDebugging(false),
    m_unregisterToken(nullptr),
    m_processId(0),
    m_ioredirect(
        { IOSystem::unnamed_pipe(), IOSystem::unnamed_pipe(), IOSystem::unnamed_pipe() },
        std::bind(&ManagedDebugger::InputCallback, this, std::placeholders::_1, std::placeholders::_2)
    )
{
    m_sharedEvalStackMachine->SetupEval(m_sharedEvaluator, m_sharedEvalHelpers, m_sharedEvalWaiter);
    m_sharedThreads->SetEvaluator(m_sharedEvaluator);
#ifdef INTEROP_DEBUGGING
    // Note, we don't care about m_interopDebugging here, since m_interopDebugging could be changed with env parsing before real start/attach.
    m_sharedEvalWaiter->SetInteropDebugger(m_sharedInteropDebugger);
#endif // INTEROP_DEBUGGING
}

ManagedDebuggerHelpers::ManagedDebuggerHelpers(IProtocol *pProtocol_) :
    ManagedDebuggerBase(pProtocol_)
{}

ManagedDebugger::ManagedDebugger(IProtocol *pProtocol_) :
    ManagedDebuggerHelpers(pProtocol_)
{}

ManagedDebuggerBase::~ManagedDebuggerBase()
{
#ifdef INTEROP_DEBUGGING
    // Note, we don't care about m_interopDebugging here, since m_interopDebugging could be changed with env parsing before real start/attach.
    m_sharedEvalWaiter->ResetInteropDebugger();
#endif // INTEROP_DEBUGGING
    m_sharedThreads->ResetEvaluator();
    m_sharedEvalStackMachine->ResetEval();
}

HRESULT ManagedDebugger::Initialize()
{
    LogFuncEntry();

    // TODO: Report capabilities and check client support
    m_startMethod = StartNone;
    return S_OK;
}

HRESULT ManagedDebuggerHelpers::RunIfReady()
{
    FrameId::invalidate();

    if (m_startMethod == StartNone || !m_isConfigurationDone)
        return S_OK;

    switch(m_startMethod)
    {
        case StartLaunch:
            return RunProcess(m_execPath, m_execArgs);
        case StartAttach:
            return AttachToProcess();
        default:
            return E_FAIL;
    }

    //Unreachable
    return E_FAIL;
}

HRESULT ManagedDebugger::Attach(int pid)
{
    LogFuncEntry();

    m_startMethod = StartAttach;
    m_processId = pid;
    return RunIfReady();
}

HRESULT ManagedDebugger::Launch(const std::string &fileExec, const std::vector<std::string> &execArgs,
                                const std::map<std::string, std::string> &env, const std::string &cwd, bool stopAtEntry)
{
    LogFuncEntry();

    m_startMethod = StartLaunch;
    m_execPath = fileExec;
    m_execArgs = execArgs;
    m_cwd = cwd;
    m_env = env;
    m_sharedBreakpoints->SetStopAtEntry(stopAtEntry);
    return RunIfReady();
}

HRESULT ManagedDebugger::ConfigurationDone()
{
    LogFuncEntry();

    m_isConfigurationDone = true;

    return RunIfReady();
}

HRESULT ManagedDebugger::Disconnect(DisconnectAction action)
{
    LogFuncEntry();
    InvalidateRewindTargets();
    InvalidateActiveFrameRemapTargets();

    bool terminate;
    switch(action)
    {
        case DisconnectDefault:
            switch(m_startMethod)
            {
                case StartLaunch:
                    terminate = true;
                    break;
                case StartAttach:
                    terminate = false;
                    break;
                default:
                    return E_FAIL;
            }
            break;
        case DisconnectTerminate:
            terminate = true;
            break;
        case DisconnectDetach:
            if (m_startMethod != StartAttach)
            {
                LOGE("Can't detach debugger form child process.\n");
                return E_INVALIDARG;
            }
            terminate = false;
            break;
        default:
            return E_FAIL;
    }

#ifdef INTEROP_DEBUGGING
    if (m_interopDebugging)
        m_sharedInteropDebugger->Shutdown();
#endif

    if (!terminate)
    {
        HRESULT Status = DetachFromProcess();
        if (SUCCEEDED(Status))
            pProtocol->EmitTerminatedEvent();

        m_ioredirect.async_cancel();
        return Status;
    }

    return TerminateProcess();
}

HRESULT ManagedDebugger::StepCommand(ThreadId threadId, StepType stepType)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    if (m_sharedEvalWaiter->IsEvalRunning())
    {
        // Important! Abort all evals before 'Step' in protocol, during eval we have inconsistent thread state.
        LOGE("Can't 'Step' during running evaluation.");
        return E_UNEXPECTED;
    }

    if (m_sharedCallbacksQueue->IsRunning())
    {
        LOGW("Can't 'Step', process already running.");
        return E_FAIL;
    }

    ToRelease<ICorDebugThread> pThread;
    IfFailRet(m_iCorProcess->GetThread(int(threadId), &pThread));
    IfFailRet(m_uniqueSteppers->SetupStep(pThread, stepType));

    InvalidateRewindTargets();
    m_sharedVariables->Clear(); // Important, must be sync with MIProtocol m_vars.clear()
    FrameId::invalidate(); // Clear all created during break frames.
    pProtocol->EmitContinuedEvent(threadId); // VSCode protocol need thread ID.

    // Note, process continue must be after event emitted, since we could get new stop event from queue here.
    if (FAILED(Status = m_sharedCallbacksQueue->Continue(m_iCorProcess)))
        LOGE("Continue failed: %s", errormessage(Status));

    return Status;
}

HRESULT ManagedDebugger::Continue(ThreadId threadId)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    if (m_sharedEvalWaiter->IsEvalRunning())
    {
        // Important! Abort all evals before 'Continue' in protocol, during eval we have inconsistent thread state.
        LOGE("Can't 'Continue' during running evaluation.");
        return E_UNEXPECTED;
    }

    if (m_sharedCallbacksQueue->IsRunning())
    {
        LOGI("Can't 'Continue', process already running.");
        return S_OK; // Send 'OK' response, but don't generate continue event.
    }

    InvalidateRewindTargets();
    m_sharedVariables->Clear(); // Important, must be sync with MIProtocol m_vars.clear()
    FrameId::invalidate(); // Clear all created during break frames.
    pProtocol->EmitContinuedEvent(threadId); // VSCode protocol need thread ID.

    // Note, process continue must be after event emitted, since we could get new stop event from queue here.
    if (FAILED(Status = m_sharedCallbacksQueue->Continue(m_iCorProcess)))
        LOGE("Continue failed: %s", errormessage(Status));

    return Status;
}

HRESULT ManagedDebugger::Pause(ThreadId lastStoppedThread, EventFormat eventFormat)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    return m_sharedCallbacksQueue->Pause(m_iCorProcess, lastStoppedThread, eventFormat);
}

HRESULT ManagedDebugger::GetThreads(std::vector<Thread> &threads, bool withNativeThreads)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

#ifdef INTEROP_DEBUGGING
    if (m_interopDebugging && withNativeThreads)
        return m_sharedThreads->GetInteropThreadsWithState(m_iCorProcess, m_sharedInteropDebugger.get(), threads);
#endif // INTEROP_DEBUGGING
    return m_sharedThreads->GetThreadsWithState(m_iCorProcess, threads);
}

VOID ManagedDebuggerHelpers::StartupCallback(IUnknown *pCordb, PVOID parameter, HRESULT hr)
{
    ManagedDebugger *self = static_cast<ManagedDebugger*>(parameter);

    self->Startup(pCordb);

    if (self->m_unregisterToken)
    {
        self->m_dbgshim.UnregisterForRuntimeStartup(self->m_unregisterToken);
        self->m_unregisterToken = nullptr;
    }
}

// From dbgshim.cpp
static bool AreAllHandlesValid(HANDLE *handleArray, DWORD arrayLength)
{
    for (DWORD i = 0; i < arrayLength; i++)
    {
        HANDLE h = handleArray[i];
        if (h == INVALID_HANDLE_VALUE)
        {
            return false;
        }
    }
    return true;
}

static HRESULT EnumerateCLRs(dbgshim_t &dbgshim, DWORD pid, HANDLE **ppHandleArray, LPWSTR **ppStringArray, DWORD *pdwArrayLength, int tryCount)
{
    int numTries = 0;
    HRESULT hr;

    while (numTries < tryCount)
    {
        hr = dbgshim.EnumerateCLRs(pid, ppHandleArray, ppStringArray, pdwArrayLength);

        // From dbgshim.cpp:
        // EnumerateCLRs uses the OS API CreateToolhelp32Snapshot which can return ERROR_BAD_LENGTH or
        // ERROR_PARTIAL_COPY. If we get either of those, we try wait 1/10th of a second try again (that
        // is the recommendation of the OS API owners).
        // In dbgshim the following condition is used:
        //  if ((hr != HRESULT_FROM_WIN32(ERROR_PARTIAL_COPY)) && (hr != HRESULT_FROM_WIN32(ERROR_BAD_LENGTH)))
        // Since we may be attaching to the process which has not loaded coreclr yes, let's give it some time to load.
        if (SUCCEEDED(hr))
        {
            // Just return any other error or if no handles were found (which means the coreclr module wasn't found yet).
            if (*ppHandleArray != NULL && *pdwArrayLength > 0)
            {

                // If EnumerateCLRs succeeded but any of the handles are INVALID_HANDLE_VALUE, then sleep and retry
                // also. This fixes a race condition where dbgshim catches the coreclr module just being loaded but
                // before g_hContinueStartupEvent has been initialized.
                if (AreAllHandlesValid(*ppHandleArray, *pdwArrayLength))
                {
                    return hr;
                }
                // Clean up memory allocated in EnumerateCLRs since this path it succeeded
                dbgshim.CloseCLREnumeration(*ppHandleArray, *ppStringArray, *pdwArrayLength);

                *ppHandleArray = NULL;
                *ppStringArray = NULL;
                *pdwArrayLength = 0;
            }
        }

        // No point in retrying in case of invalid arguments or no such process
        if (hr == E_INVALIDARG || hr == E_FAIL)
            return hr;

        // Sleep and retry enumerating the runtimes
        USleep(100*1000);
        numTries++;

        // if (m_canceled)
        // {
        //     break;
        // }
    }

    // Indicate a timeout
    hr = HRESULT_FROM_WIN32(ERROR_TIMEOUT);

    return hr;
}

static std::string GetCLRPath(dbgshim_t &dbgshim, DWORD pid, int timeoutSec = 3)
{
    HANDLE* pHandleArray;
    LPWSTR* pStringArray;
    DWORD dwArrayLength;
    const int tryCount = timeoutSec * 10; // 100ms interval between attempts
    if (FAILED(EnumerateCLRs(dbgshim, pid, &pHandleArray, &pStringArray, &dwArrayLength, tryCount)) || dwArrayLength == 0)
        return std::string();

    std::string result = to_utf8(pStringArray[0]);

    dbgshim.CloseCLREnumeration(pHandleArray, pStringArray, dwArrayLength);

    return result;
}

HRESULT ManagedDebuggerHelpers::Startup(IUnknown *punk)
{
    HRESULT Status;

    ToRelease<ICorDebug> iCorDebug;
    IfFailRet(punk->QueryInterface(IID_ICorDebug, (void **)&iCorDebug));

    IfFailRet(iCorDebug->Initialize());

    if (m_clrPath.empty())
        m_clrPath = GetCLRPath(m_dbgshim, m_processId);

    m_sharedCallbacksQueue.reset(new CallbacksQueue(*this));
    m_uniqueManagedCallback.reset(new ManagedCallback(*this, m_sharedCallbacksQueue));
    Status = iCorDebug->SetManagedHandler(m_uniqueManagedCallback.get());
    if (FAILED(Status))
    {
        iCorDebug->Terminate();
        m_uniqueManagedCallback.reset();
        m_sharedCallbacksQueue.reset();
        return Status;
    }

    ToRelease<ICorDebugProcess> iCorProcess;
    Status = iCorDebug->DebugActiveProcess(m_processId, FALSE, &iCorProcess);
    if (FAILED(Status))
    {
        iCorDebug->Terminate();
        m_uniqueManagedCallback.reset();
        m_sharedCallbacksQueue.reset();
        return Status;
    }

    std::unique_lock<Utility::RWLock::Writer> lockProcessRWLock(m_debugProcessRWLock.writer);

    m_iCorProcess = iCorProcess.Detach();
    m_iCorDebug = iCorDebug.Detach();

    lockProcessRWLock.unlock();

#ifdef FEATURE_PAL
    GetWaitpid().SetupTrackingPID(m_processId);
#endif // FEATURE_PAL

    return S_OK;
}

static bool IsDirExists(const char* const path)
{
    struct stat info;

    if (stat(path, &info) != 0)
        return false;

    if (!(info.st_mode & S_IFDIR))
        return false;

    return true;
}

static void SetCustomEnvironmentArgs(std::map<std::string, std::string> &env, bool hotReload)
{
#ifdef NCDB_DOTNET_STARTUP_HOOK
    if (hotReload)
    {
        auto find = env.find(envDOTNET_STARTUP_HOOKS);
        if (find != env.end())
            find->second = find->second + delimiterDOTNET_STARTUP_HOOKS + NCDB_DOTNET_STARTUP_HOOK;
        else
            env[envDOTNET_STARTUP_HOOKS] = NCDB_DOTNET_STARTUP_HOOK;
    }
#else
    (void)hotReload; // suppress warning about unused param
#endif // NCDB_DOTNET_STARTUP_HOOK
}

static void PrepareSystemEnvironmentArg(const std::map<std::string, std::string> &env, std::vector<char> &outEnv, bool hotReload, bool &interopDebugging)
{
    // We need to append the environ values with keeping the current process environment block.
    // It works equal for any platrorms in coreclr CreateProcessW(), but not critical for Linux.
    std::map<std::string, std::string> envMap;
    if (GetSystemEnvironmentAsMap(envMap) != -1)
    {
        // Override the system value (PATHs appending needs a complex implementation)
        for (const auto &pair : env)
        {
            if (pair.first == envDOTNET_STARTUP_HOOKS && !envMap[pair.first].empty())
            {
                envMap[pair.first] = envMap[pair.first] + delimiterDOTNET_STARTUP_HOOKS + pair.second;
                continue;
            }
#ifdef INTEROP_DEBUGGING
            else if (pair.first == envNCDB_INTEROP_DEBUGGING)
            {
                interopDebugging = true;
                continue;
            }
#else
            (void)interopDebugging; // suppress warning about unused param
#endif // INTEROP_DEBUGGING
            envMap[pair.first] = pair.second;
        }
    }
    else
    {
        envMap = env;
    }
    SetCustomEnvironmentArgs(envMap, hotReload);
    for (const auto &pair : envMap)
    {
        outEnv.insert(outEnv.end(), pair.first.begin(), pair.first.end());
        outEnv.push_back('=');
        outEnv.insert(outEnv.end(), pair.second.begin(), pair.second.end());
        outEnv.push_back('\0');
    }
    // Environtment variable should looks like: "Var=Value\0OtherVar=OtherValue\0\0"
    if (!outEnv.empty())
        outEnv.push_back('\0');
}

HRESULT ManagedDebuggerHelpers::RunProcess(const std::string& fileExec, const std::vector<std::string>& execArgs)
{
    HRESULT Status;

    IfFailRet(CheckNoProcess());

    std::ostringstream ss;
    ss << "\"" << fileExec << "\"";
    for (const std::string &arg : execArgs)
    {
        if (arg.empty())
        {
            continue;
        }

        // https://github.com/dotnet/diagnostics/blob/3a9d1f8a7ba2a6cae33f6953af77086bfbe02906/src/shared/pal/src/thread/process.cpp#L3898-L3902
        // Note: dbgshim uses different logic for building arguments compared to Windows.
        // dbgshim uses simpler logic and cannot properly handle arguments ending with `\"`, for example "D:\\path\\to to\\dir\\".
        // When wrapped in quotes, dbgshim interprets the trailing `\"` as an escaped quote, resulting in
        // `D:\path\to to\dir\"` which corrupts the next argument parsing.
        if (arg.back() == '\\' && arg.find(' ') == std::string::npos)
        {
            ss << " " << arg;
        }
        else if (arg.back() == '\\')
        {
#ifdef _WIN32
            ss << " \"" << arg << R"(\")";
#else
            LOGE("Arguments with spaces and a trailing backslash are not supported by dbgshim: %s", arg.c_str());
#endif
        }
        else
        {
            ss << " \"" << arg << "\"";
        }
    }

    m_clrPath.clear();

    HANDLE resumeHandle = 0; // Fake thread handle for the process resume

#ifdef INTEROP_DEBUGGING
    bool prevInteropDebuggingStatus = !!m_interopDebugging;
#endif INTEROP_DEBUGGING

    std::vector<char> outEnv;
    PrepareSystemEnvironmentArg(m_env, outEnv, m_hotReload, m_interopDebugging);

#ifdef INTEROP_DEBUGGING
    if ((!!m_interopDebugging) != prevInteropDebuggingStatus)
    {
        // In case of interop debugging we depend on SIGCHLD set to SIG_DFL by init code.
        // Note, debugger include corhost (CoreCLR) that could setup sigaction for SIGCHLD and ruin interop debugger work.
        SetSigactionMode(!!m_interopDebugging);
    }
#endif INTEROP_DEBUGGING

    // cwd in launch.json set working directory for debugger https://code.visualstudio.com/docs/python/debugging#_cwd
    if (!m_cwd.empty())
    {
        if (!IsDirExists(m_cwd.c_str()) || !SetWorkDir(m_cwd))
            m_cwd.clear();
    }

    Status = m_ioredirect.exec([&]() -> HRESULT {
            IfFailRet(m_dbgshim.CreateProcessForLaunch(reinterpret_cast<LPWSTR>(const_cast<WCHAR*>(to_utf16(ss.str()).c_str())),
                                     /* Suspend process */ TRUE,
                                     outEnv.empty() ? NULL : &outEnv[0],
                                     m_cwd.empty() ? NULL : reinterpret_cast<LPCWSTR>(to_utf16(m_cwd).c_str()),
                                     &m_processId, &resumeHandle));
            return Status;
        });

    if (FAILED(Status))
        return Status;

#ifdef FEATURE_PAL
    GetWaitpid().SetupTrackingPID(m_processId);
#endif // FEATURE_PAL

    IfFailRet(m_dbgshim.RegisterForRuntimeStartup(m_processId, ManagedDebugger::StartupCallback, this, &m_unregisterToken));

    // Resume the process so that StartupCallback can run
    IfFailRet(m_dbgshim.ResumeProcess(resumeHandle));
    m_dbgshim.CloseResumeHandle(resumeHandle);

    std::unique_lock<std::mutex> lockAttachedMutex(m_processAttachedMutex);
    if (!m_processAttachedCV.wait_for(lockAttachedMutex, startupWaitTimeout, [this]{return m_processAttachedState == ProcessAttachedState::Attached;}))
        return E_FAIL;

    pProtocol->EmitExecEvent(PID{m_processId}, fileExec);

    return S_OK;
}

HRESULT ManagedDebuggerBase::CheckNoProcess()
{
    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);

    if (!m_iCorProcess)
        return S_OK;

    std::unique_lock<std::mutex> lockAttachedMutex(m_processAttachedMutex);
    if (m_processAttachedState == ProcessAttachedState::Attached)
        return E_FAIL; // Already attached
    lockAttachedMutex.unlock();

    Cleanup();
    return S_OK;
}

HRESULT ManagedDebuggerHelpers::DetachFromProcess()
{
    do {
        std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
        std::lock_guard<std::mutex> guardAttachedMutex(m_processAttachedMutex);
        if (m_processAttachedState == ProcessAttachedState::Unattached)
            break;

        if (!m_iCorProcess)
            return E_FAIL;

        BOOL procRunning = FALSE;
        if (SUCCEEDED(m_iCorProcess->IsRunning(&procRunning)) && procRunning == TRUE)
            m_iCorProcess->Stop(0);

        DisableAllBreakpointsAndSteppers();

        HRESULT Status;
        if (FAILED(Status = m_iCorProcess->Detach()))
            LOGE("Process detach failed: %s", errormessage(Status));

        m_processAttachedState = ProcessAttachedState::Unattached; // Since we free process object anyway, reset process attached state.
    } while(0);

    Cleanup();
    return S_OK;
}

HRESULT ManagedDebuggerHelpers::TerminateProcess()
{
    do {
        std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
        std::unique_lock<std::mutex> lockAttachedMutex(m_processAttachedMutex);
        if (m_processAttachedState == ProcessAttachedState::Unattached)
            break;

        if (!m_iCorProcess)
            return E_FAIL;

        BOOL procRunning = FALSE;
        if (SUCCEEDED(m_iCorProcess->IsRunning(&procRunning)) && procRunning == TRUE)
            m_iCorProcess->Stop(0);

        DisableAllBreakpointsAndSteppers();

        HRESULT Status;
        if (SUCCEEDED(Status = m_iCorProcess->Terminate(0)))
        {
            m_processAttachedCV.wait(lockAttachedMutex, [this]{return m_processAttachedState == ProcessAttachedState::Unattached;});
            break;
        }

        LOGE("Process terminate failed: %s", errormessage(Status));
        m_processAttachedState = ProcessAttachedState::Unattached; // Since we free process object anyway, reset process attached state.
    } while(0);

    Cleanup();
    return S_OK;
}

void ManagedDebuggerBase::Cleanup()
{
    m_sharedModules->CleanupAllModules();
    m_sharedEvalHelpers->Cleanup();
    m_sharedVariables->Clear(); // Important, must be sync with MIProtocol m_vars.clear()
    pProtocol->Cleanup();

    std::lock_guard<Utility::RWLock::Writer> guardProcessRWLock(m_debugProcessRWLock.writer);

    assert((m_iCorProcess && m_iCorDebug && m_uniqueManagedCallback && m_sharedCallbacksQueue) ||
           (!m_iCorProcess && !m_iCorDebug && !m_uniqueManagedCallback && !m_sharedCallbacksQueue));

    if (!m_iCorProcess)
        return;

    m_iCorProcess.Free();

    m_iCorDebug->Terminate();
    m_iCorDebug.Free();

    if (m_uniqueManagedCallback->GetRefCount() > 0)
    {
        LOGW("ManagedCallback was not properly released by ICorDebug");
    }
    m_uniqueManagedCallback.reset(nullptr);
    m_sharedCallbacksQueue = nullptr;
}

HRESULT ManagedDebuggerHelpers::AttachToProcess()
{
    HRESULT Status;

    IfFailRet(CheckNoProcess());

    m_clrPath = GetCLRPath(m_dbgshim, m_processId);
    if (m_clrPath.empty())
        return E_INVALIDARG; // Unable to find libcoreclr.so

    WCHAR pBuffer[100];
    DWORD dwLength;
    IfFailRet(m_dbgshim.CreateVersionStringFromModule(
        m_processId,
        reinterpret_cast<LPCWSTR>(to_utf16(m_clrPath).c_str()),
        pBuffer,
        _countof(pBuffer),
        &dwLength));

    ToRelease<IUnknown> pCordb;

    IfFailRet(m_dbgshim.CreateDebuggingInterfaceFromVersionEx(CorDebugVersion_4_0, pBuffer, &pCordb));

    m_unregisterToken = nullptr;
    IfFailRet(Startup(pCordb));

    std::unique_lock<std::mutex> lockAttachedMutex(m_processAttachedMutex);
    if (!m_processAttachedCV.wait_for(lockAttachedMutex, startupWaitTimeout, [this]{return m_processAttachedState == ProcessAttachedState::Attached;}))
        return E_FAIL;

    return S_OK;
}

HRESULT ManagedDebugger::GetExceptionInfo(ThreadId threadId, ExceptionInfo &exceptionInfo)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    ToRelease<ICorDebugThread> iCorThread;
    IfFailRet(m_iCorProcess->GetThread(int(threadId), &iCorThread));
    return m_sharedBreakpoints->GetExceptionInfo(iCorThread, exceptionInfo);
}

HRESULT ManagedDebugger::SetExceptionBreakpoints(const std::vector<ExceptionBreakpoint> &exceptionBreakpoints, std::vector<Breakpoint> &breakpoints)
{
    LogFuncEntry();
    return m_sharedBreakpoints->SetExceptionBreakpoints(exceptionBreakpoints, breakpoints);
}

HRESULT ManagedDebugger::UpdateLineBreakpoint(int id, int linenum, Breakpoint &breakpoint)
{
    LogFuncEntry();

    bool haveProcess = HaveDebugProcess();
    return m_sharedBreakpoints->UpdateLineBreakpoint(haveProcess, id, linenum, breakpoint);
}

#ifdef INTEROP_DEBUGGING

static bool isNativeSource(const std::string &filename)
{
    // Detect native code breakpoint by extension:
    // https://gcc.gnu.org/onlinedocs/gcc-12.2.0/gcc/Overall-Options.html
    static std::unordered_set<std::string> fileExtension{"c", "C", "cc", "cp", "cxx", "cpp", "CPP", "c++",
                                                         "i", "ii", "m", "M", "mi", "mm", "mii",
                                                         "h", "H", "hh", "hp", "hxx", "hpp", "HPP", "h++", "tpp"};

    std::size_t lastDotPos = filename.rfind('.');
    if (lastDotPos != std::string::npos)
    {
        std::string fileExt = filename.substr(lastDotPos + 1);
        auto find = fileExtension.find(fileExt);
        if (find != fileExtension.end())
        {
            return true;
        }
    }

    return false;
}

#endif // INTEROP_DEBUGGING

HRESULT ManagedDebugger::SetLineBreakpoints(const std::string& filename,
                                            const std::vector<LineBreakpoint> &lineBreakpoints,
                                            std::vector<Breakpoint> &breakpoints)
{
    LogFuncEntry();

#ifdef INTEROP_DEBUGGING
    // Also set interop line breakpoints for native code
    if (m_interopDebugging && isNativeSource(filename))
        return m_sharedInteropDebugger->SetLineBreakpoints(filename, lineBreakpoints, breakpoints);
#endif // INTEROP_DEBUGGING

    bool haveProcess = HaveDebugProcess();
    return m_sharedBreakpoints->SetLineBreakpoints(haveProcess, filename, lineBreakpoints, breakpoints);
}

HRESULT ManagedDebugger::SetFuncBreakpoints(const std::vector<FuncBreakpoint> &funcBreakpoints, std::vector<Breakpoint> &breakpoints)
{
    LogFuncEntry();

#ifdef INTEROP_DEBUGGING
    // Set interop function breakpoints for native code, ignore errors.
    if (m_interopDebugging)
        m_sharedInteropDebugger->SetFuncBreakpoints(funcBreakpoints, breakpoints);
#endif // INTEROP_DEBUGGING

    bool haveProcess = HaveDebugProcess();
    return m_sharedBreakpoints->SetFuncBreakpoints(haveProcess, funcBreakpoints, breakpoints);
}

HRESULT ManagedDebugger::BreakpointActivate(int id, bool act)
{
    if (SUCCEEDED(m_sharedBreakpoints->BreakpointActivate(id, act)))
        return S_OK;

#ifdef INTEROP_DEBUGGING
    // Note, we don't care about m_interopDebugging here, since breakpoint setup could be start before m_interopDebugging changes with env parsing.
    return m_sharedInteropDebugger->BreakpointActivate(id, act);
#else
    return E_FAIL;
#endif // INTEROP_DEBUGGING
}

HRESULT ManagedDebugger::AllBreakpointsActivate(bool act)
{
    HRESULT Status1 = m_sharedBreakpoints->AllBreakpointsActivate(act);

#ifdef INTEROP_DEBUGGING
    // Note, we don't care about m_interopDebugging here, since breakpoint setup could be start before m_interopDebugging changes with env parsing.
    HRESULT Status2 = m_sharedInteropDebugger->AllBreakpointsActivate(act);
    return FAILED(Status1) ? Status1 : Status2;
#else
    return Status1;
#endif // INTEROP_DEBUGGING
}

HRESULT ManagedDebuggerBase::GetFrameLocation(ICorDebugFrame *pFrame, ThreadId threadId, FrameLevel level, StackFrame &stackFrame, bool hotReloadAwareCaller)
{
    HRESULT Status;

    stackFrame = StackFrame(threadId, level, "");
    if (FAILED(TypePrinter::GetMethodName(pFrame, stackFrame.methodName)))
        stackFrame.methodName = "Unnamed method in optimized code";

    ToRelease<ICorDebugFunction> pFunc;
    IfFailRet(pFrame->GetFunction(&pFunc));

    ToRelease<ICorDebugModule> pModule;
    IfFailRet(pFunc->GetModule(&pModule));

    ULONG32 methodVersion = 1;
    ULONG32 currentVersion = 1;
    if (m_hotReload)
    {
        // In case current (top) code version is 1, executed in this frame method version can't be not 1.
        if (SUCCEEDED(pFunc->GetCurrentVersionNumber(&currentVersion)) && currentVersion != 1)
        {
            ToRelease<ICorDebugCode> pCode;
            IfFailRet(pFunc->GetILCode(&pCode));
            IfFailRet(pCode->GetVersionNumber(&methodVersion));
        }

        if (!hotReloadAwareCaller && methodVersion != currentVersion)
        {
            std::string moduleNamePrefix;
            WCHAR name[mdNameLen];
            ULONG32 name_len = 0;
            if (SUCCEEDED(pModule->GetName(_countof(name), &name_len, name)))
            {
                moduleNamePrefix = to_utf8(name);
                std::size_t i = moduleNamePrefix.find_last_of("/\\");
                if (i != std::string::npos)
                    moduleNamePrefix = moduleNamePrefix.substr(i + 1);
                moduleNamePrefix += "!";
            }

            // [Outdated Code] module.dll!MethodName()
            stackFrame.methodName = "[Outdated Code] " + moduleNamePrefix + stackFrame.methodName;

            return S_OK;
        }
    }

    ULONG32 ilOffset;
    Modules::SequencePoint sp;
    if (SUCCEEDED(m_sharedModules->GetFrameILAndSequencePoint(pFrame, ilOffset, sp)))
    {
        stackFrame.source = Source(sp.document);
        stackFrame.line = sp.startLine;
        stackFrame.column = sp.startColumn;
        stackFrame.endLine = sp.endLine;
        stackFrame.endColumn = sp.endColumn;
    }

    mdMethodDef methodToken;
    IfFailRet(pFrame->GetFunctionToken(&methodToken));

    ULONG32 nOffset = 0;
    ToRelease<ICorDebugNativeFrame> pNativeFrame;
    IfFailRet(pFrame->QueryInterface(IID_ICorDebugNativeFrame, (LPVOID*) &pNativeFrame));
    IfFailRet(pNativeFrame->GetIP(&nOffset));

    IfFailRet(GetModuleId(pModule, stackFrame.moduleId));

    stackFrame.clrAddr.methodToken = methodToken;
    stackFrame.clrAddr.ilOffset = ilOffset;
    stackFrame.clrAddr.nativeOffset = nOffset;
    stackFrame.clrAddr.methodVersion = methodVersion;

    stackFrame.addr = 0; // This method used for managed stop events only, but all implemented protocols don't use `addr` in managed stop events outputs.

    if (stackFrame.clrAddr.ilOffset != 0)
        stackFrame.activeStatementFlags |= StackFrame::ActiveStatementFlags::PartiallyExecuted;
    if (methodVersion == currentVersion)
        stackFrame.activeStatementFlags |= StackFrame::ActiveStatementFlags::MethodUpToDate;
    else
        stackFrame.activeStatementFlags |= StackFrame::ActiveStatementFlags::Stale;

    return S_OK;
}

static std::string GetModuleNameForFrame(ICorDebugFrame *pFrame)
{
    ToRelease<ICorDebugFunction> pFunc;
    if (!pFrame || FAILED(pFrame->GetFunction(&pFunc)))
        return std::string{};

    ToRelease<ICorDebugModule> pModule;
    if (FAILED(pFunc->GetModule(&pModule)))
        return std::string{};

    WCHAR name[mdNameLen];
    ULONG32 name_len = 0;
    if (FAILED(pModule->GetName(_countof(name), &name_len, name)))
        return std::string{};

    return GetBasename(to_utf8(name));
}

HRESULT ManagedDebuggerBase::GetManagedStackTrace(ICorDebugThread *pThread, ThreadId threadId, FrameLevel startFrame, unsigned maxFrames,
                                                  std::vector<StackFrame> &stackFrames, int &totalFrames, bool hotReloadAwareCaller)
{
    LogFuncEntry();

    HRESULT Status;
    int currentFrame = -1;

    auto AddFrameStatementFlag = [&] ()
    {
        if (currentFrame == 0)
            stackFrames.back().activeStatementFlags |= StackFrame::ActiveStatementFlags::LeafFrame;
        else
            stackFrames.back().activeStatementFlags |= StackFrame::ActiveStatementFlags::NonLeafFrame;
    };

#ifdef INTEROP_DEBUGGING
    // In case debug session without interop, we merge "[CoreCLR Native Frame]" and "user's native frame" into "[Native Frames]".
    const std::string FrameCLRNativeText = m_interopDebugging ? "[CoreCLR Native Frame]" : "[Native Frames]";
#else
    // CoreCLR native frame + at least one user's native frame (note, `FrameNative` case should never happen for not interop build)
    static const std::string FrameCLRNativeText = "[Native Frames]";
#endif // INTEROP_DEBUGGING

    IfFailRet(WalkFrames(pThread, [&](
        FrameType frameType,
        std::uintptr_t addr,
        ICorDebugFrame *pFrame,
        NativeFrame *pNative)
    {
        currentFrame++;

        if (currentFrame < int(startFrame))
            return S_OK;
        if (maxFrames != 0 && currentFrame >= int(startFrame) + int(maxFrames))
            return S_OK;

        switch(frameType)
        {
            case FrameUnknown:
                stackFrames.emplace_back(threadId, FrameLevel{currentFrame}, "?");
                stackFrames.back().addr = addr;
                AddFrameStatementFlag();
                break;
            case FrameNative:
                stackFrames.emplace_back(threadId, FrameLevel{currentFrame}, pNative->procName);
                stackFrames.back().addr = pNative->addr;
                stackFrames.back().unknownFrameAddr = pNative->unknownFrameAddr;
                stackFrames.back().moduleOrLibName = pNative->libName;
                stackFrames.back().source = Source(pNative->fullSourcePath);
                stackFrames.back().line = pNative->lineNum;
                AddFrameStatementFlag();
                break;
            case FrameCLRNative:
                stackFrames.emplace_back(threadId, FrameLevel{currentFrame}, FrameCLRNativeText);
                stackFrames.back().addr = addr;
                stackFrames.back().unknownFrameAddr = !addr; // Could be 0 here only in case some CoreCLR registers context issue.
                AddFrameStatementFlag();
                break;
            case FrameCLRInternal:
                {
                    ToRelease<ICorDebugInternalFrame> pInternalFrame;
                    IfFailRet(pFrame->QueryInterface(IID_ICorDebugInternalFrame, (LPVOID*) &pInternalFrame));
                    CorDebugInternalFrameType corFrameType;
                    IfFailRet(pInternalFrame->GetFrameType(&corFrameType));
                    std::string name = "[";
                    name += GetInternalTypeName(corFrameType);
                    name += "]";
                    stackFrames.emplace_back(threadId, FrameLevel{currentFrame}, name);
                    stackFrames.back().addr = addr;
                    stackFrames.back().unknownFrameAddr = !addr; // Could be 0 here only in case some CoreCLR registers context issue.
                    AddFrameStatementFlag();
                }
                break;
            case FrameCLRManaged:
                {
                    StackFrame stackFrame;
                    GetFrameLocation(pFrame, threadId, FrameLevel{currentFrame}, stackFrame, hotReloadAwareCaller);
                    stackFrames.push_back(stackFrame);
                    stackFrames.back().addr = addr;
                    stackFrames.back().unknownFrameAddr = !addr; // Could be 0 here only in case some CoreCLR registers context issue.
                    stackFrames.back().moduleOrLibName = GetModuleNameForFrame(pFrame);
                    AddFrameStatementFlag();
                }
                break;
        }

        return S_OK;
    }));

    totalFrames = currentFrame + 1;
    ExceptionInfo exceptionInfo;
    bool analyzeExceptions = true;
    if (!stackFrames.empty())
    {
        analyzeExceptions = analyzeExceptions && (stackFrames.front().line == 0);
    }

#ifdef INTEROP_DEBUGGING
    analyzeExceptions = analyzeExceptions && !m_interopDebugging;
#endif // INTEROP_DEBUGGING

    if (!analyzeExceptions)
        return S_OK;

//  Sometimes Coreclr may return the empty stack frame in exception info
//  for some unknown reason. In that case the 2nd attempt is usually successful.
//  If even the 3rd attempt failed, there is almost no chances to get data successfuly.
    int tries = 3;
    for(int tryCount = 0; tryCount < tries; tryCount++)
    {
        if (SUCCEEDED(GetExceptionInfo (threadId, exceptionInfo)))
        {
            std::stringstream ss(exceptionInfo.details.stackTrace);
            int countOfNewFrames = 0;
            int currentFrame = -1;
            size_t sizeofStackFrame = stackFrames.size();

//          The stackTrace strings from ExceptionInfo usually looks like:
//          at Program.Func2(string[] strvect) in /home/user/work/vscode_test/utils.cs:line 122
//          at Program.Func1<int, char>() in /home/user/work/vscode_test/utils.cs:line 78
//          at Program.Main() in /home/user/work/vscode_test/Program.cs:line 25
//          at Program.Main() in C:\Users/localuser/work/vscode_test\Program.cs:line 25
            while (!ss.eof())
            {
                std::string line;
                std::getline(ss, line, '\n');
                size_t lastcolon = line.find_last_of(':');
                if (lastcolon == std::string::npos)
                    continue;

                size_t beginpath = line.find_first_of('/');
                if (beginpath == std::string::npos)
                {
                    beginpath = line.find_first_of('\\');
                    if (beginpath == std::string::npos)
                    {
                        continue;
                    }
                }

                // append disk name, if exists
                beginpath = line.find_last_of(' ', beginpath);
                if (beginpath == std::string::npos)
                    continue;

                beginpath++;
                if (beginpath >= lastcolon)
                    continue;

                // remove leading spaces and the first word ("at" for the case of English locale)
                size_t beginname = line.find_first_not_of(' ');
                if (beginname == std::string::npos)
                    continue;

                beginname = line.find_first_of(' ', beginname);
                if (beginname == std::string::npos)
                    continue;
                beginname++;

                // the function name ends with the last ')' before the beginning of fullpath
                size_t endname = line.find_last_of(')', beginpath);
                if (endname == std::string::npos)
                    continue;
                endname++;

                if (beginname >= endname)
                    continue;

                // look for the line number after the last colon
                size_t beginlinenum = line.find_first_of("0123456789", lastcolon);
                size_t endlinenum = line.find_first_not_of("0123456789", beginlinenum);
                if (beginlinenum == std::string::npos)
                    continue;

                currentFrame++;
                if (currentFrame < (int)startFrame || (maxFrames != 0 && currentFrame >= (int)startFrame + (int)maxFrames))
                    continue;

                int l{std::stoi(line.substr(beginlinenum, endlinenum))};
                stackFrames.emplace_back(threadId, FrameLevel{currentFrame}, line.substr(beginname, endname - beginname));
                stackFrames.back().source = Source(line.substr(beginpath, lastcolon - beginpath));
                stackFrames.back().line = stackFrames.back().endLine = l;
                countOfNewFrames++;
            }

            if (countOfNewFrames > 0)
            {
                stackFrames.erase(stackFrames.begin(), stackFrames.begin() + sizeofStackFrame);
                totalFrames = currentFrame + 1;
                break;
            }
        }
    }

    return S_OK;
}

#ifdef INTEROP_DEBUGGING
HRESULT ManagedDebuggerBase::GetNativeStackTrace(ThreadId threadId, FrameLevel startFrame, unsigned maxFrames, std::vector<StackFrame> &stackFrames, int &totalFrames)
{
    LogFuncEntry();

    HRESULT Status;
    int currentFrame = -1;

    Status = m_sharedInteropDebugger->UnwindNativeFrames(int(threadId), true, 0, nullptr, [&](NativeFrame &nativeFrame)
    {
        currentFrame++;

        if (currentFrame < int(startFrame))
            return S_OK;
        if (maxFrames != 0 && currentFrame >= int(startFrame) + int(maxFrames))
            return S_OK;

        stackFrames.emplace_back(threadId, FrameLevel{currentFrame}, nativeFrame.procName);
        stackFrames.back().addr = nativeFrame.addr;
        stackFrames.back().unknownFrameAddr = nativeFrame.unknownFrameAddr;
        stackFrames.back().moduleOrLibName = nativeFrame.libName;
        stackFrames.back().source = Source(nativeFrame.fullSourcePath);
        stackFrames.back().line = nativeFrame.lineNum;

        if (currentFrame == 0)
            stackFrames.back().activeStatementFlags |= StackFrame::ActiveStatementFlags::LeafFrame;
        else
            stackFrames.back().activeStatementFlags |= StackFrame::ActiveStatementFlags::NonLeafFrame;

        return S_OK;
    });

    totalFrames = currentFrame + 1;
    
    return Status;
}
#endif // INTEROP_DEBUGGING

HRESULT ManagedDebugger::GetStackTrace(ThreadId threadId, FrameLevel startFrame, unsigned maxFrames, std::vector<StackFrame> &stackFrames, int &totalFrames, bool hotReloadAwareCaller)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    ToRelease<ICorDebugThread> pThread;
    if (SUCCEEDED(Status = m_iCorProcess->GetThread(int(threadId), &pThread)))
        return GetManagedStackTrace(pThread, threadId, startFrame, maxFrames, stackFrames, totalFrames, hotReloadAwareCaller);

#ifdef INTEROP_DEBUGGING
    // E_INVALIDARG for ICorDebugProcess::GetThread() mean thread is not managed (can't found ICorDebugThread object that represents the thread)
    if (m_interopDebugging && Status == E_INVALIDARG)
        return GetNativeStackTrace(threadId, startFrame, maxFrames, stackFrames, totalFrames);
#endif // INTEROP_DEBUGGING

    return Status;
}

int ManagedDebugger::GetNamedVariables(uint32_t variablesReference)
{
    LogFuncEntry();

    return m_sharedVariables->GetNamedVariables(variablesReference);
}

HRESULT ManagedDebugger::GetVariables(
    uint32_t variablesReference,
    VariablesFilter filter,
    int start,
    int count,
    std::vector<Variable> &variables)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    return m_sharedVariables->GetVariables(m_iCorProcess, variablesReference, filter, start, count, variables);
}

HRESULT ManagedDebugger::GetScopes(FrameId frameId, std::vector<Scope> &scopes)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    return m_sharedVariables->GetScopes(m_iCorProcess, frameId, scopes);
}

HRESULT ManagedDebugger::Evaluate(FrameId frameId, const std::string &expression, Variable &variable, std::string &output)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    return m_sharedVariables->Evaluate(m_iCorProcess, frameId, expression, variable, output);
}

void ManagedDebugger::CancelEvalRunning()
{
    LogFuncEntry();

    m_sharedEvalWaiter->CancelEvalRunning();
}

HRESULT ManagedDebugger::SetVariable(const std::string &name, const std::string &value, uint32_t ref, std::string &output)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    return m_sharedVariables->SetVariable(m_iCorProcess, name, value, ref, output);
}

HRESULT ManagedDebugger::SetExpression(FrameId frameId, const std::string &expression, int evalFlags, const std::string &value, std::string &output)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    return m_sharedVariables->SetExpression(m_iCorProcess, frameId, expression, evalFlags, value, output);
}

HRESULT ManagedDebuggerBase::GetRewindFrameIdentity(
    ThreadId threadId,
    FrameId frameId,
    IDebugger::RewindFrameIdentity &identity,
    ToRelease<ICorDebugFrame> &frame,
    ToRelease<ICorDebugILFrame> &ilFrame,
    ToRelease<ICorDebugFunction> &function,
    ToRelease<ICorDebugCode> &code,
    ToRelease<ICorDebugModule> &module,
    StackFrame *stackFrame)
{
    HRESULT Status;

    if (int(frameId.getThread()) != int(threadId) || int(frameId.getLevel()) != 0)
        return E_INVALIDARG;

    {
        std::lock_guard<std::mutex> lock(m_lastStoppedMutex);
        if (int(m_lastStoppedThreadId) != int(threadId))
            return CORDBG_E_PROCESS_NOT_SYNCHRONIZED;
    }

    ToRelease<ICorDebugThread> thread;
    IfFailRet(m_iCorProcess->GetThread(int(threadId), &thread));
    IfFailRet(GetFrameAt(thread, FrameLevel(0), &frame));
    if (!frame)
        return E_FAIL;

    IfFailRet(frame->QueryInterface(IID_ICorDebugILFrame, (LPVOID*) &ilFrame));
    IfFailRet(frame->GetFunction(&function));
    IfFailRet(function->GetILCode(&code));
    IfFailRet(function->GetModule(&module));

    CorDebugMappingResult mappingResult;
    ULONG32 ilOffset = 0;
    IfFailRet(ilFrame->GetIP(&ilOffset, &mappingResult));
    if (mappingResult == MAPPING_UNMAPPED_ADDRESS || mappingResult == MAPPING_NO_INFO)
        return E_FAIL;

    mdMethodDef methodToken = 0;
    ULONG32 functionVersion = 0;
    std::string moduleMvid;
    IfFailRet(frame->GetFunctionToken(&methodToken));
    IfFailRet(code->GetVersionNumber(&functionVersion));
    IfFailRet(GetModuleId(module, moduleMvid));

    identity.stopId = CurrentStopId();
    identity.threadId = threadId;
    identity.frameId = frameId;
    identity.moduleMvid = moduleMvid;
    identity.methodToken = methodToken;
    identity.functionVersion = functionVersion;
    identity.ilOffset = ilOffset;

    if (stackFrame)
        IfFailRet(GetFrameLocation(frame, threadId, FrameLevel(0), *stackFrame, true));

    return S_OK;
}

HRESULT ManagedDebuggerBase::ValidateExceptionRegions(
    ICorDebugCode *code,
    ICorDebugModule *module,
    mdMethodDef methodToken,
    ULONG32 currentIlOffset,
    ULONG32 targetIlOffset,
    std::string &reasonCode,
    std::string &reason)
{
    HRESULT Status;
    std::vector<CorDebugEHClause> clauses;
    ToRelease<ICorDebugILCode> ilCode;
    Status = code->QueryInterface(IID_ICorDebugILCode, (LPVOID*) &ilCode);
    if (SUCCEEDED(Status))
    {
        ULONG32 count = 0;
        Status = ilCode->GetEHClauses(0, &count, nullptr);
        if (SUCCEEDED(Status) && count > 0)
        {
            clauses.resize(count);
            ULONG32 written = 0;
            Status = ilCode->GetEHClauses(count, &written, clauses.data());
            if (SUCCEEDED(Status))
                clauses.resize(written);
        }
    }

    if (FAILED(Status))
        Status = ReadExceptionClausesFromModule(module, methodToken, clauses);
    if (FAILED(Status))
    {
        reasonCode = "exception_regions_unavailable";
        reason = "The debugger could not inspect the method's exception-region metadata.";
        return Status;
    }
    if (clauses.empty())
        return S_OK;

    std::vector<std::size_t> currentTryRegions;
    std::vector<std::size_t> targetTryRegions;
    auto InRange = [](ULONG32 offset, ULONG32 start, ULONG32 length)
    {
        return uint64_t(offset) >= uint64_t(start) &&
            uint64_t(offset) < uint64_t(start) + uint64_t(length);
    };

    constexpr ULONG32 FilterClause = 0x00000001;
    for (std::size_t index = 0; index < clauses.size(); ++index)
    {
        const auto &clause = clauses[index];
        const bool currentInHandler = InRange(currentIlOffset, clause.HandlerOffset, clause.HandlerLength);
        const bool targetInHandler = InRange(targetIlOffset, clause.HandlerOffset, clause.HandlerLength);
        const bool currentInFilter = (clause.Flags & FilterClause) != 0 &&
            currentIlOffset >= clause.FilterOffset && currentIlOffset < clause.HandlerOffset;
        const bool targetInFilter = (clause.Flags & FilterClause) != 0 &&
            targetIlOffset >= clause.FilterOffset && targetIlOffset < clause.HandlerOffset;

        if (currentInHandler || targetInHandler || currentInFilter || targetInFilter)
        {
            reasonCode = "exception_handler_transition";
            reason = "Instruction rewind is not allowed from or into an exception handler, filter, finally, or fault region.";
            return S_FALSE;
        }

        if (InRange(currentIlOffset, clause.TryOffset, clause.TryLength))
            currentTryRegions.push_back(index);
        if (InRange(targetIlOffset, clause.TryOffset, clause.TryLength))
            targetTryRegions.push_back(index);
    }

    if (currentTryRegions != targetTryRegions)
    {
        reasonCode = "exception_region_transition";
        reason = "Instruction rewind cannot cross a protected exception region boundary.";
        return S_FALSE;
    }

    return S_OK;
}

HRESULT ManagedDebugger::ResolveRewindTarget(
    ThreadId threadId,
    FrameId frameId,
    const std::string &sourceFile,
    int line,
    RewindTarget &target)
{
    LogFuncEntry();

    if (sourceFile.empty() || line <= 0)
        return E_INVALIDARG;

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    if (m_sharedEvalWaiter->IsEvalRunning() || m_sharedCallbacksQueue->IsRunning())
        return CORDBG_E_PROCESS_NOT_SYNCHRONIZED;

    ToRelease<ICorDebugFrame> frame;
    ToRelease<ICorDebugILFrame> ilFrame;
    ToRelease<ICorDebugFunction> function;
    ToRelease<ICorDebugCode> code;
    ToRelease<ICorDebugModule> module;
    IfFailRet(GetRewindFrameIdentity(threadId, frameId, target.frame, frame, ilFrame, function, code, module));

    ULONG32 currentVersion = 0;
    IfFailRet(function->GetCurrentVersionNumber(&currentVersion));
    if (currentVersion != target.frame.functionVersion)
    {
        target.safety = RewindSafety::Unknown;
        target.reasonCode = "stale_method_version";
        target.reason = "The active frame is executing an older method version; source rewind resolution is deferred to code-edit-plus-rewind.";
        return S_OK;
    }

    CORDB_ADDRESS moduleAddress = 0;
    IfFailRet(module->GetBaseAddress(&moduleAddress));

    unsigned sourcePathIndex = 0;
    std::vector<ModulesSources::resolved_bp_t> resolvedPoints;
    Status = m_sharedModules->ResolveBreakpoint(moduleAddress, sourceFile, sourcePathIndex, line, resolvedPoints);
    if (FAILED(Status))
    {
        target.safety = RewindSafety::Unknown;
        target.reasonCode = "source_not_resolved";
        target.reason = "The requested source file or line could not be resolved using the active module symbols.";
        return S_OK;
    }

    const ModulesSources::resolved_bp_t *resolved = nullptr;
    bool resolvedOtherMethod = false;
    for (const auto &candidate : resolvedPoints)
    {
        if (candidate.startLine > line || candidate.endLine < line)
            continue;
        if (candidate.methodToken != target.frame.methodToken)
        {
            resolvedOtherMethod = true;
            continue;
        }

        std::string candidateMvid;
        if (FAILED(GetModuleId(candidate.iCorModule, candidateMvid)) || candidateMvid != target.frame.moduleMvid)
            continue;
        resolved = &candidate;
        break;
    }

    if (!resolved)
    {
        target.safety = resolvedOtherMethod ? RewindSafety::Unsafe : RewindSafety::Unknown;
        target.reasonCode = resolvedOtherMethod ? "same_method_required" : "sequence_point_not_found";
        target.reason = resolvedOtherMethod
            ? "The requested source line resolves outside the active method."
            : "No executable sequence point on the requested line belongs to the active method.";
        return S_OK;
    }

    target.requestedLine = line;
    target.resolvedLine = resolved->startLine;
    target.targetIlOffset = resolved->ilOffset;
    std::string resolvedPath;
    if (SUCCEEDED(m_sharedModules->GetSourceFullPathByIndex(sourcePathIndex, resolvedPath)))
        target.source = Source(resolvedPath);
    else
        target.source = Source(sourceFile);

    Modules::SequencePoint sequencePoint;
    if (SUCCEEDED(m_sharedModules->GetSequencePointByILOffset(
        moduleAddress,
        target.frame.methodToken,
        target.frame.functionVersion,
        target.targetIlOffset,
        sequencePoint)))
    {
        target.resolvedLine = sequencePoint.startLine;
        target.resolvedColumn = sequencePoint.startColumn;
        target.source = Source(sequencePoint.document);
    }

    if (target.targetIlOffset >= target.frame.ilOffset)
    {
        target.safety = RewindSafety::Unsafe;
        target.reasonCode = target.targetIlOffset == target.frame.ilOffset ? "rewind_noop" : "forward_movement_rejected";
        target.reason = target.targetIlOffset == target.frame.ilOffset
            ? "The requested source line is the current instruction location."
            : "Vision instruction control accepts backward movement only.";
        return S_OK;
    }

    Status = ValidateExceptionRegions(
        code,
        module,
        target.frame.methodToken,
        target.frame.ilOffset,
        target.targetIlOffset,
        target.reasonCode,
        target.reason);
    if (Status == S_FALSE)
    {
        target.safety = RewindSafety::Unsafe;
        return S_OK;
    }
    if (FAILED(Status))
    {
        target.safety = RewindSafety::Unknown;
        target.reasonCode = "exception_regions_unavailable";
        target.reason = "The debugger could not verify exception-region safety for the requested movement.";
        return S_OK;
    }

    target.canSetIpHResult = ilFrame->CanSetIP(target.targetIlOffset);
    if (target.canSetIpHResult != S_OK)
    {
        target.safety = RewindSafety::Unsafe;
        target.reasonCode = "runtime_rejected_target";
        target.reason = "ICorDebugILFrame::CanSetIP rejected the requested instruction location.";
        return S_OK;
    }

    target.safety = RewindSafety::Safe;
    target.reasonCode = "safe";
    target.reason = "The target is a backward sequence point in the same method and passed all safety checks.";
    target.targetId = NewRewindTargetId();
    target.expiresInMs = int(std::chrono::duration_cast<std::chrono::milliseconds>(rewindTargetLifetime).count());

    const auto now = std::chrono::steady_clock::now();
    StoredRewindTarget stored;
    stored.id = target.targetId;
    stored.frame = target.frame;
    stored.sourceFile = target.source.path;
    stored.resolvedLine = target.resolvedLine;
    stored.resolvedColumn = target.resolvedColumn;
    stored.targetIlOffset = target.targetIlOffset;
    stored.createdAt = now;
    stored.expiresAt = now + rewindTargetLifetime;

    std::lock_guard<std::mutex> lock(m_rewindTargetsMutex);
    for (auto it = m_rewindTargets.begin(); it != m_rewindTargets.end();)
    {
        if (it->second.expiresAt <= now)
            it = m_rewindTargets.erase(it);
        else
            ++it;
    }
    if (m_rewindTargets.size() >= maxRewindTargets)
    {
        auto oldest = std::min_element(
            m_rewindTargets.begin(),
            m_rewindTargets.end(),
            [](const std::pair<const std::string, StoredRewindTarget> &left,
               const std::pair<const std::string, StoredRewindTarget> &right)
            {
                return left.second.createdAt < right.second.createdAt;
            });
        if (oldest != m_rewindTargets.end())
            m_rewindTargets.erase(oldest);
    }
    m_rewindTargets.emplace(stored.id, std::move(stored));
    return S_OK;
}

HRESULT ManagedDebugger::SetInstructionPointer(
    const std::string &targetId,
    const RewindFrameIdentity &expectedFrame,
    InstructionPointerResult &result)
{
    LogFuncEntry();

    if (targetId.empty())
        return E_INVALIDARG;

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    if (m_sharedEvalWaiter->IsEvalRunning() || m_sharedCallbacksQueue->IsRunning())
    {
        result.reasonCode = "debuggee_not_stopped";
        result.reason = "The debuggee must be stopped before moving the instruction pointer.";
        return CORDBG_E_PROCESS_NOT_SYNCHRONIZED;
    }

    StoredRewindTarget stored;
    {
        std::lock_guard<std::mutex> lock(m_rewindTargetsMutex);
        auto found = m_rewindTargets.find(targetId);
        if (found == m_rewindTargets.end())
        {
            result.reasonCode = "rewind_target_not_found";
            result.reason = "The rewind target does not exist or was invalidated by a debug-state transition.";
            return E_INVALIDARG;
        }
        stored = found->second;
        m_rewindTargets.erase(found);
    }

    if (stored.expiresAt <= std::chrono::steady_clock::now())
    {
        result.reasonCode = "rewind_target_expired";
        result.reason = "The rewind target expired before it was applied.";
        return E_INVALIDARG;
    }

    if (!FrameIdentityEquals(stored.frame, expectedFrame))
    {
        result.reasonCode = "rewind_frame_mismatch";
        result.reason = "The expected frame identity does not match the resolved rewind target.";
        return E_INVALIDARG;
    }

    ToRelease<ICorDebugFrame> frame;
    ToRelease<ICorDebugILFrame> ilFrame;
    ToRelease<ICorDebugFunction> function;
    ToRelease<ICorDebugCode> code;
    ToRelease<ICorDebugModule> module;
    IfFailRet(GetRewindFrameIdentity(
        expectedFrame.threadId,
        expectedFrame.frameId,
        result.previousFrame,
        frame,
        ilFrame,
        function,
        code,
        module));

    if (!FrameIdentityEquals(result.previousFrame, expectedFrame))
    {
        result.reasonCode = "rewind_target_stale";
        result.reason = "The stopped frame changed after the rewind target was resolved.";
        return E_INVALIDARG;
    }

    Status = ValidateExceptionRegions(
        code,
        module,
        result.previousFrame.methodToken,
        result.previousFrame.ilOffset,
        stored.targetIlOffset,
        result.reasonCode,
        result.reason);
    if (Status != S_OK)
    {
        if (result.reasonCode.empty())
        {
            result.reasonCode = "rewind_safety_unknown";
            result.reason = "The debugger could not revalidate exception-region safety.";
        }
        return FAILED(Status) ? Status : E_ACCESSDENIED;
    }

    result.canSetIpHResult = ilFrame->CanSetIP(stored.targetIlOffset);
    if (result.canSetIpHResult != S_OK)
    {
        result.reasonCode = "runtime_rejected_target";
        result.reason = "ICorDebugILFrame::CanSetIP rejected the target during final validation.";
        return E_ACCESSDENIED;
    }

    result.setIpHResult = ilFrame->SetIP(stored.targetIlOffset);
    if (result.setIpHResult != S_OK)
    {
        result.reasonCode = "set_ip_failed";
        result.reason = "ICorDebugILFrame::SetIP failed.";
        return result.setIpHResult;
    }

    result.moved = true;
    result.handlesInvalidated = true;
    m_sharedVariables->Clear();
    FrameId::invalidate();
    {
        std::lock_guard<std::mutex> lock(m_lastStoppedMutex);
        ++m_stoppedEpoch;
    }
    InvalidateRewindTargets();
    m_sharedBreakpoints->SetLastStoppedIlOffset(m_iCorProcess, expectedFrame.threadId);

    const FrameId newFrameId(expectedFrame.threadId, FrameLevel(0));
    ToRelease<ICorDebugFrame> newFrame;
    ToRelease<ICorDebugILFrame> newIlFrame;
    ToRelease<ICorDebugFunction> newFunction;
    ToRelease<ICorDebugCode> newCode;
    ToRelease<ICorDebugModule> newModule;
    Status = GetRewindFrameIdentity(
        expectedFrame.threadId,
        newFrameId,
        result.currentFrame,
        newFrame,
        newIlFrame,
        newFunction,
        newCode,
        newModule,
        &result.stoppedFrame);
    if (FAILED(Status))
    {
        result.warnings.emplace_back("The instruction pointer moved, but the debugger could not reacquire complete frame evidence.");
        return S_OK;
    }

    if (result.currentFrame.moduleMvid != result.previousFrame.moduleMvid ||
        result.currentFrame.methodToken != result.previousFrame.methodToken)
    {
        result.warnings.emplace_back("The instruction pointer moved, but the reacquired frame identity no longer matches the original method.");
    }

    return S_OK;
}

HRESULT ManagedDebuggerBase::GetInvocationId(
    ICorDebugThread *thread,
    ICorDebugFrame *frame,
    const IDebugger::RewindFrameIdentity &identity,
    std::string &invocationId)
{
    HRESULT Status;
    (void)thread;
    CORDB_ADDRESS activeStart = 0;
    CORDB_ADDRESS activeEnd = 0;
    IfFailRet(frame->GetStackRange(&activeStart, &activeEnd));

    CORDB_ADDRESS callerStart = 0;
    CORDB_ADDRESS callerEnd = 0;
    ToRelease<ICorDebugFrame> caller;
    if (SUCCEEDED(frame->GetCaller(&caller)) && caller)
        caller->GetStackRange(&callerStart, &callerEnd);

    std::ostringstream material;
    material << int(identity.threadId) << ':'
             << identity.moduleMvid << ':'
             << identity.methodToken << ':'
             << std::hex << activeStart << ':' << activeEnd << ':' << callerStart << ':' << callerEnd;
    const std::size_t hash = std::hash<std::string>{}(material.str());
    std::ostringstream encoded;
    encoded << "inv_" << std::hex << std::setfill('0') << std::setw(sizeof(std::size_t) * 2) << hash;
    invocationId = encoded.str();
    return S_OK;
}

HRESULT ManagedDebugger::InspectFrameGeneration(
    ThreadId threadId,
    FrameId frameId,
    FrameGenerationEvidence &evidence)
{
    HRESULT Status;
    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    IfFailRet(CheckDebugProcess());
    if (m_sharedEvalWaiter->IsEvalRunning() || m_sharedCallbacksQueue->IsRunning())
        return CORDBG_E_PROCESS_NOT_SYNCHRONIZED;

    ToRelease<ICorDebugFrame> frame;
    ToRelease<ICorDebugILFrame> ilFrame;
    ToRelease<ICorDebugFunction> function;
    ToRelease<ICorDebugCode> code;
    ToRelease<ICorDebugModule> module;
    IfFailRet(GetRewindFrameIdentity(threadId, frameId, evidence.frame, frame, ilFrame, function, code, module));
    IfFailRet(function->GetCurrentVersionNumber(&evidence.latestGeneration));

    ToRelease<ICorDebugThread> thread;
    IfFailRet(m_iCorProcess->GetThread(int(threadId), &thread));
    return GetInvocationId(thread, frame, evidence.frame, evidence.invocationId);
}

HRESULT ManagedDebugger::ResolveActiveFrameRemapTarget(
    ThreadId threadId,
    FrameId frameId,
    const std::string &sourceFile,
    int line,
    const std::string &moduleMvid,
    uint32_t methodToken,
    ULONG32 appliedGeneration,
    ActiveFrameRemapTarget &target)
{
    HRESULT Status;
    LogFuncEntry();
    if (sourceFile.empty() || line <= 0 || moduleMvid.empty() || methodToken == 0 || appliedGeneration <= 1)
        return E_INVALIDARG;

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    IfFailRet(CheckDebugProcess());
    if (m_sharedEvalWaiter->IsEvalRunning() || m_sharedCallbacksQueue->IsRunning())
        return CORDBG_E_PROCESS_NOT_SYNCHRONIZED;

    ToRelease<ICorDebugFrame> frame;
    ToRelease<ICorDebugILFrame> ilFrame;
    ToRelease<ICorDebugFunction> function;
    ToRelease<ICorDebugCode> code;
    ToRelease<ICorDebugModule> module;
    IfFailRet(GetRewindFrameIdentity(threadId, frameId, target.frame, frame, ilFrame, function, code, module));
    if (target.frame.moduleMvid != moduleMvid || target.frame.methodToken != methodToken)
    {
        target.safety = RewindSafety::Unsafe;
        target.reasonCode = "active_method_mismatch";
        target.reason = "The applied update does not target the active frame method.";
        return S_OK;
    }

    ULONG32 latestGeneration = 0;
    IfFailRet(function->GetCurrentVersionNumber(&latestGeneration));
    if (latestGeneration != appliedGeneration || target.frame.functionVersion >= appliedGeneration)
    {
        target.safety = RewindSafety::Unknown;
        target.reasonCode = "applied_generation_mismatch";
        target.reason = "The active frame and applied update generations could not be correlated.";
        return S_OK;
    }

    CORDB_ADDRESS moduleAddress = 0;
    IfFailRet(module->GetBaseAddress(&moduleAddress));
    unsigned sourcePathIndex = 0;
    std::vector<ModulesSources::resolved_bp_t> resolvedPoints;
    Status = m_sharedModules->ResolveBreakpoint(moduleAddress, sourceFile, sourcePathIndex, line, resolvedPoints);
    if (FAILED(Status))
    {
        target.safety = RewindSafety::Unknown;
        target.reasonCode = "updated_source_not_resolved";
        target.reason = "The updated entry source line could not be resolved.";
        return S_OK;
    }

    const ModulesSources::resolved_bp_t *resolved = nullptr;
    for (const auto &candidate : resolvedPoints)
    {
        std::string candidateMvid;
        if (candidate.startLine <= line && candidate.endLine >= line &&
            candidate.methodToken == methodToken &&
            SUCCEEDED(GetModuleId(candidate.iCorModule, candidateMvid)) &&
            candidateMvid == moduleMvid)
        {
            resolved = &candidate;
            break;
        }
    }
    if (!resolved)
    {
        target.safety = RewindSafety::Unknown;
        target.reasonCode = "updated_sequence_point_not_found";
        target.reason = "No updated-generation sequence point matched the entry checkpoint.";
        return S_OK;
    }

    ToRelease<ICorDebugThread> thread;
    IfFailRet(m_iCorProcess->GetThread(int(threadId), &thread));
    IfFailRet(GetInvocationId(thread, frame, target.frame, target.invocationId));
    target.requestedLine = line;
    target.resolvedLine = resolved->startLine;
    target.targetIlOffset = resolved->ilOffset;
    target.source = Source(sourceFile);
    target.appliedGeneration = appliedGeneration;
    target.safety = RewindSafety::Safe;
    target.reasonCode = "safe";
    target.reason = "The target identifies the updated generation of the same active method invocation.";
    target.targetId = NewRewindTargetId();
    target.expiresInMs = int(std::chrono::duration_cast<std::chrono::milliseconds>(rewindTargetLifetime).count());

    StoredActiveFrameRemapTarget stored;
    stored.id = target.targetId;
    stored.frame = target.frame;
    stored.sourceFile = sourceFile;
    stored.resolvedLine = target.resolvedLine;
    stored.resolvedColumn = target.resolvedColumn;
    stored.targetIlOffset = target.targetIlOffset;
    stored.appliedGeneration = appliedGeneration;
    stored.invocationId = target.invocationId;
    stored.expiresAt = std::chrono::steady_clock::now() + rewindTargetLifetime;
    std::lock_guard<std::mutex> lock(m_activeFrameRemapMutex);
    m_activeFrameRemapTargets.clear();
    m_activeFrameRemapTargets.emplace(stored.id, std::move(stored));
    return S_OK;
}

HRESULT ManagedDebugger::ArmActiveFrameRemap(
    const std::string &targetId,
    const RewindFrameIdentity &expectedFrame)
{
    std::lock_guard<std::mutex> lock(m_activeFrameRemapMutex);
    auto found = m_activeFrameRemapTargets.find(targetId);
    if (found == m_activeFrameRemapTargets.end() || found->second.expiresAt <= std::chrono::steady_clock::now())
        return E_INVALIDARG;
    if (!FrameIdentityEquals(found->second.frame, expectedFrame))
        return E_INVALIDARG;
    m_armedActiveFrameRemapId = targetId;
    return S_OK;
}

HRESULT ManagedDebuggerBase::TryApplyArmedActiveFrameRemap(
    ICorDebugThread *thread,
    ICorDebugFunction *oldFunction,
    ICorDebugFunction *newFunction,
    ULONG32 oldIlOffset)
{
    HRESULT Status;
    (void)oldIlOffset;
    StoredActiveFrameRemapTarget target;
    {
        std::lock_guard<std::mutex> lock(m_activeFrameRemapMutex);
        if (m_armedActiveFrameRemapId.empty())
            return S_FALSE;
        auto found = m_activeFrameRemapTargets.find(m_armedActiveFrameRemapId);
        if (found == m_activeFrameRemapTargets.end())
            return S_FALSE;
        target = found->second;
    }

    mdMethodDef oldToken = 0;
    mdMethodDef newToken = 0;
    ToRelease<ICorDebugFunction2> oldFunction2;
    ToRelease<ICorDebugFunction2> newFunction2;
    ULONG32 oldGeneration = 0;
    ULONG32 newGeneration = 0;
    IfFailRet(oldFunction->GetToken(&oldToken));
    IfFailRet(newFunction->GetToken(&newToken));
    IfFailRet(oldFunction->QueryInterface(IID_ICorDebugFunction2, (LPVOID*) &oldFunction2));
    IfFailRet(newFunction->QueryInterface(IID_ICorDebugFunction2, (LPVOID*) &newFunction2));
    IfFailRet(oldFunction2->GetVersionNumber(&oldGeneration));
    IfFailRet(newFunction2->GetVersionNumber(&newGeneration));
    if (oldToken != target.frame.methodToken || newToken != target.frame.methodToken ||
        oldGeneration != target.frame.functionVersion || newGeneration != target.appliedGeneration)
        return E_INVALIDARG;

    ToRelease<ICorDebugFrame> frame;
    IfFailRet(thread->GetActiveFrame(&frame));
    ToRelease<ICorDebugILFrame2> ilFrame2;
    IfFailRet(frame->QueryInterface(IID_ICorDebugILFrame2, (LPVOID*) &ilFrame2));
    IfFailRet(ilFrame2->RemapFunction(target.targetIlOffset));

    ActiveFrameRemapEvent event;
    event.targetId = target.id;
    event.invocationId = target.invocationId;
    event.moduleMvid = target.frame.moduleMvid;
    event.methodToken = target.frame.methodToken;
    event.oldFunctionVersion = oldGeneration;
    event.newFunctionVersion = newGeneration;
    event.targetIlOffset = target.targetIlOffset;
    event.source = Source(target.sourceFile);
    event.line = target.resolvedLine;
    {
        std::lock_guard<std::mutex> lock(m_activeFrameRemapMutex);
        m_lastActiveFrameRemapEvent = event;
        m_haveActiveFrameRemapEvent = true;
        m_activeFrameRemapTargets.clear();
        m_armedActiveFrameRemapId.clear();
    }
    m_sharedVariables->Clear();
    FrameId::invalidate();
    InvalidateRewindTargets();
    return S_OK;
}

bool ManagedDebuggerBase::TakeActiveFrameRemapEvent(ActiveFrameRemapEvent &event)
{
    std::lock_guard<std::mutex> lock(m_activeFrameRemapMutex);
    if (!m_haveActiveFrameRemapEvent)
        return false;
    event = m_lastActiveFrameRemapEvent;
    m_haveActiveFrameRemapEvent = false;
    return true;
}


void ManagedDebugger::FindFileNames(string_view pattern, unsigned limit, SearchCallback cb)
{
    LogFuncEntry();
    m_sharedModules->FindFileNames(pattern, limit, cb);
}

void ManagedDebugger::FindFunctions(string_view pattern, unsigned limit, SearchCallback cb)
{
    LogFuncEntry();
    m_sharedModules->FindFunctions(pattern, limit, cb);
}

void ManagedDebugger::FindVariables(ThreadId thread, FrameLevel framelevel, string_view pattern, unsigned limit, SearchCallback cb)
{
    LogFuncEntry();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    if (FAILED(CheckDebugProcess()))
        return;

    StackFrame frame{thread, framelevel, ""};
    std::vector<Scope> scopes;
    std::vector<Variable> variables;
    HRESULT status = m_sharedVariables->GetScopes(m_iCorProcess, frame.id, scopes);
    if (FAILED(status))
    {
        LOGW("GetScopes failed: %s", errormessage(status));
        return;
    }

    if (scopes.empty() || scopes[0].variablesReference == 0)
    {
        LOGW("no variables in visible scopes");
        return;
    }

    status = m_sharedVariables->GetVariables(m_iCorProcess, scopes[0].variablesReference, VariablesNamed, 0, 0, variables);
    if (FAILED(status))
    {
        LOGW("GetVariables failed: %s", errormessage(status));
        return;
    }

    for (const Variable& var : variables)
    {
        LOGD("var: '%s'", var.name.c_str());

        if (limit == 0)
            break;

        auto pos = var.name.find(pattern.data(), 0, pattern.size());
        if (pos != std::string::npos && (pos == 0 || var.name[pos-1] == '.'))
        {
            limit--;
            cb(var.name.c_str());
        }
    }
}


void ManagedDebuggerBase::InputCallback(IORedirectHelper::StreamType type, span<char> text)
{
    pProtocol->EmitOutputEvent(type == IOSystem::Stderr ? OutputStdErr : OutputStdOut, {text.begin(), text.size()});
}


void ManagedDebugger::EnumerateBreakpoints(std::function<bool (const BreakpointInfo&)>&& callback)
{
    LogFuncEntry();
    return m_sharedBreakpoints->EnumerateBreakpoints(std::move(callback));
}

static HRESULT GetModuleOfCurrentThreadCode(ICorDebugProcess *pProcess, int lastStoppedThreadId, ICorDebugModule **ppModule)
{
    HRESULT Status;
    ToRelease<ICorDebugThread> pThread;
    IfFailRet(pProcess->GetThread(lastStoppedThreadId, &pThread));

    ToRelease<ICorDebugFrame> pFrame;
    IfFailRet(pThread->GetActiveFrame(&pFrame));
    if (pFrame == nullptr)
        return E_FAIL;

    mdMethodDef methodToken;
    IfFailRet(pFrame->GetFunctionToken(&methodToken));
    ToRelease<ICorDebugFunction> pFunc;
    IfFailRet(pFrame->GetFunction(&pFunc));
    return pFunc->GetModule(ppModule);
}

HRESULT ManagedDebugger::GetSourceFile(const std::string &sourcePath, char** fileBuf, int* fileLen)
{
    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);
    HRESULT Status;
    IfFailRet(CheckDebugProcess());

    ToRelease<ICorDebugModule> pModule;
    IfFailRet(GetModuleOfCurrentThreadCode(m_iCorProcess, int(GetLastStoppedThreadId()), &pModule));
    return m_sharedModules->GetSource(pModule, sourcePath, fileBuf, fileLen);
}

void ManagedDebugger::FreeUnmanaged(PVOID mem)
{
    Interop::CoTaskMemFree(mem);
}

IDebugger::AsyncResult ManagedDebugger::ProcessStdin(InStream& stream)
{
    LogFuncEntry();
    return m_ioredirect.async_input(stream);
}


void ManagedDebugger::SetJustMyCode(bool enable)
{
    m_justMyCode = enable;
    m_uniqueSteppers->SetJustMyCode(enable);
    m_sharedBreakpoints->SetJustMyCode(enable);
}

void ManagedDebugger::SetStepFiltering(bool enable)
{
    m_stepFiltering = enable;
    m_uniqueSteppers->SetStepFiltering(enable);
}

HRESULT ManagedDebugger::SetHotReload(bool enable)
{
    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);

    if (m_iCorProcess && m_startMethod == StartAttach)
        return CORDBG_E_CANNOT_BE_ON_ATTACH;

    m_hotReload = enable;

    return S_OK;
}

#ifdef INTEROP_DEBUGGING
void ManagedDebugger::SetInteropDebugging(bool enable)
{
    m_interopDebugging = enable;
}
#endif

static HRESULT ApplyMetadataAndILDeltas(Modules *pModules, const std::string &dllFileName, const std::string &deltaMD, const std::string &deltaIL)
{
    HRESULT Status;

    std::ifstream deltaILFileStream(deltaIL, std::ios::in | std::ios::binary | std::ios::ate);
    std::ifstream deltaMDFileStream(deltaMD, std::ios::in | std::ios::binary | std::ios::ate);

    if (!deltaILFileStream.is_open() || !deltaMDFileStream.is_open())
        return COR_E_FILENOTFOUND;

    auto deltaILSize = deltaILFileStream.tellg();
    if (deltaILSize < 0)
        return E_FAIL;
    std::unique_ptr<BYTE[]> deltaILMemBlock(new BYTE[(size_t)deltaILSize]);
    deltaILFileStream.seekg(0, std::ios::beg);
    deltaILFileStream.read((char*)deltaILMemBlock.get(), deltaILSize);

    auto deltaMDSize = deltaMDFileStream.tellg();
    if (deltaMDSize < 0)
        return E_FAIL;
    std::unique_ptr<BYTE[]> deltaMDMemBlock(new BYTE[(size_t)deltaMDSize]);
    deltaMDFileStream.seekg(0, std::ios::beg);
    deltaMDFileStream.read((char*)deltaMDMemBlock.get(), deltaMDSize);

    ToRelease<ICorDebugModule> pModule;
    IfFailRet(pModules->GetModuleWithName(dllFileName, &pModule, true));
    ToRelease<ICorDebugModule2> pModule2;
    IfFailRet(pModule->QueryInterface(IID_ICorDebugModule2, (LPVOID *)&pModule2));
    IfFailRet(pModule2->ApplyChanges((ULONG)deltaMDSize, deltaMDMemBlock.get(), (ULONG)deltaILSize, deltaILMemBlock.get()));

    return S_OK;
}

HRESULT ManagedDebuggerBase::ApplyPdbDeltaAndLineUpdates(const std::string &dllFileName, const std::string &deltaPDB, const std::string &lineUpdates,
                                                         std::string &updatedDLL, std::unordered_set<mdTypeDef> &updatedTypeTokens)
{
    HRESULT Status;
    ToRelease<ICorDebugModule> pModule;
    IfFailRet(m_sharedModules->GetModuleWithName(dllFileName, &pModule, true));

    std::unordered_set<mdMethodDef> pdbMethodTokens;
    IfFailRet(m_sharedModules->ApplyPdbDeltaAndLineUpdates(pModule, m_justMyCode, deltaPDB, lineUpdates, pdbMethodTokens));

    updatedDLL = GetModuleFileName(pModule);
    for (const auto &methodToken : pdbMethodTokens)
    {
        mdTypeDef typeDef;
        ToRelease<ICorDebugFunction> iCorFunction;
        ToRelease<ICorDebugClass> iCorClass;
        if (SUCCEEDED(pModule->GetFunctionFromToken(methodToken, &iCorFunction)) &&
            SUCCEEDED(iCorFunction->GetClass(&iCorClass)) &&
            SUCCEEDED(iCorClass->GetToken(&typeDef)))
            updatedTypeTokens.insert(typeDef);
    }

    // Since we could have new code lines and new methods added, check all breakpoints again.
    std::vector<BreakpointEvent> events;
    m_sharedBreakpoints->UpdateBreakpointsOnHotReload(pModule, pdbMethodTokens, events);
    for (const BreakpointEvent &event : events)
        pProtocol->EmitBreakpointEvent(event);

    return S_OK;
}

HRESULT ManagedDebuggerBase::FindEvalCapableThread(ToRelease<ICorDebugThread> &pThread)
{
    ThreadId lastStoppedId = GetLastStoppedThreadId();
    std::vector<ThreadId> threadIds;
    m_sharedThreads->GetThreadIds(threadIds);
    for (size_t i = 0; i < threadIds.size(); ++i)
    {
        if (threadIds[i] == lastStoppedId)
        {
            std::swap(threadIds[0], threadIds[i]);
            break;
        }
    }

    for (auto &threadId : threadIds)
    {
        ToRelease<ICorDebugValue> iCorValue;
        if (SUCCEEDED(m_iCorProcess->GetThread(int(threadId), &pThread)) &&
            SUCCEEDED(m_sharedEvalHelpers->CreateString(pThread, "test_string", &iCorValue)))
        {
            return S_OK;
        }
        pThread.Free();
    }

    return E_FAIL;
}

HRESULT ManagedDebugger::HotReloadApplyDeltas(const std::string &dllFileName, const std::string &moduleMvid,
                                              const std::vector<uint32_t> &updatedMethodTokens,
                                              const std::string &deltaMD, const std::string &deltaIL,
                                              const std::string &deltaPDB, const std::string &lineUpdates,
                                              std::vector<HotReloadMethodGeneration> &methodGenerations,
                                              std::string &failureStage)
{
    LogFuncEntry();
    failureStage = "initialize";
    InvalidateRewindTargets();
    InvalidateActiveFrameRemapTargets();

    std::lock_guard<Utility::RWLock::Reader> guardProcessRWLock(m_debugProcessRWLock.reader);

    if (!m_iCorProcess)
        return E_FAIL;

    // Deltas can be applied only on stopped debuggee process. For Hot Reload scenario we temporary stop it and continue after deltas applied.
    HRESULT Status;
    failureStage = "stop_process";
    IfFailRet(m_sharedCallbacksQueue->Stop(m_iCorProcess));
    bool continueProcess = (Status == S_OK); // Was stopped by m_sharedCallbacksQueue->Stop() call.

    ToRelease<ICorDebugModule> module;
    failureStage = "resolve_module";
    IfFailRet(m_sharedModules->GetModuleWithName(dllFileName, &module, true));
    std::string actualMvid;
    failureStage = "read_module_mvid";
    IfFailRet(GetModuleId(module, actualMvid));
    if (!moduleMvid.empty() && actualMvid != moduleMvid)
        return E_INVALIDARG;

    methodGenerations.clear();
    failureStage = "read_previous_generation";
    for (uint32_t token : updatedMethodTokens)
    {
        ToRelease<ICorDebugFunction> function;
        ULONG32 previousGeneration = 0;
        IfFailRet(module->GetFunctionFromToken(token, &function));
        IfFailRet(function->GetCurrentVersionNumber(&previousGeneration));
        HotReloadMethodGeneration generation;
        generation.methodToken = token;
        generation.previousGeneration = previousGeneration;
        generation.appliedGeneration = 0;
        methodGenerations.push_back(generation);
    }

    failureStage = "apply_metadata_il";
    IfFailRet(ApplyMetadataAndILDeltas(m_sharedModules.get(), dllFileName, deltaMD, deltaIL));
    failureStage = "read_applied_generation";
    for (auto &generation : methodGenerations)
    {
        ToRelease<ICorDebugFunction> function;
        IfFailRet(module->GetFunctionFromToken(generation.methodToken, &function));
        IfFailRet(function->GetCurrentVersionNumber(&generation.appliedGeneration));
        if (generation.appliedGeneration <= generation.previousGeneration)
            return E_FAIL;
    }
    std::string updatedDLL;
    std::unordered_set<mdTypeDef> updatedTypeTokens;
    failureStage = "apply_pdb_line_updates";
    IfFailRet(ApplyPdbDeltaAndLineUpdates(dllFileName, deltaPDB, lineUpdates, updatedDLL, updatedTypeTokens));

    failureStage = "notify_metadata_update_handlers";
    ToRelease<ICorDebugThread> pThread;
    if (SUCCEEDED(FindEvalCapableThread(pThread)))
        IfFailRet(HotReloadHelpers::UpdateApplication(pThread, m_sharedModules.get(), m_sharedEvaluator.get(), m_sharedEvalHelpers.get(), updatedDLL, updatedTypeTokens));
    else
        IfFailRet(m_sharedBreakpoints->SetHotReloadBreakpoint(updatedDLL, updatedTypeTokens));

    if (continueProcess)
    {
        failureStage = "continue_process";
        IfFailRet(m_sharedCallbacksQueue->Continue(m_iCorProcess));
    }

    failureStage.clear();
    return S_OK;
}

HRESULT ManagedDebugger::HotReloadApplyDeltas(
    const std::string &dllFileName,
    const std::string &deltaMD,
    const std::string &deltaIL,
    const std::string &deltaPDB,
    const std::string &lineUpdates)
{
    std::vector<HotReloadMethodGeneration> methodGenerations;
    std::string failureStage;
    return HotReloadApplyDeltas(
        dllFileName,
        std::string(),
        std::vector<uint32_t>(),
        deltaMD,
        deltaIL,
        deltaPDB,
        lineUpdates,
        methodGenerations,
        failureStage);
}

} // namespace netcoredbg
