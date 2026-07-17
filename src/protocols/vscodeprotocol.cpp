// Copyright (c) 2018 Samsung Electronics Co., LTD
// Distributed under the MIT License.
// See the LICENSE file in the project root for more information.

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <map>
#include <unordered_set>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <limits>
#include <thread>
#include <future>
#include <fstream>

// note: order matters, vscodeprotocol.h should be included before winerror.h
#include "protocols/vscodeprotocol.h"
#include "winerror.h"

#include "interfaces/idebugger.h"
#include "utils/streams.h"
#include "utils/torelease.h"
#include "utils/utf.h"
#include "utils/logger.h"
#include "protocols/escaped_string.h"

// for convenience
using json = nlohmann::json;

namespace netcoredbg
{

namespace
{
    std::unordered_map<std::string, ExceptionBreakpointFilter> g_VSCodeFilters{
        {"all",            ExceptionBreakpointFilter::THROW},
        {"user-unhandled", ExceptionBreakpointFilter::USER_UNHANDLED}};

    const std::string TWO_CRLF("\r\n\r\n");
    const std::string CONTENT_LENGTH("Content-Length: ");

    const std::string LOG_COMMAND("-> (C) ");
    const std::string LOG_RESPONSE("<- (R) ");
    const std::string LOG_EVENT("<- (E) ");

    // Make sure we continue add new commands into queue only after current command execution is finished.
    // Note, configurationDone: prevent deadlock in _dup() call during std::getline() from stdin in main thread.
    const std::unordered_set<std::string> g_syncCommandExecutionSet{
        "configurationDone", "disconnect", "terminate"};
    // Commands, that trigger command queue canceling routine.
    const std::unordered_set<std::string> g_cancelCommandQueueSet{
        "disconnect", "terminate", "continue", "next", "stepIn", "stepOut"};
    // Don't cancel commands related to debugger configuration. For example, breakpoint setup could be done in any time (even if process don't attached at all).
    const std::unordered_set<std::string> g_debuggerSetupCommandSet{
        "initialize", "setExceptionBreakpoints", "configurationDone", "setBreakpoints", "launch", "disconnect", "terminate", "attach", "setFunctionBreakpoints",
        "visionApplyHotReload"};

    constexpr int VISION_HOT_RELOAD_PROTOCOL_VERSION = 2;
    constexpr int VISION_INSTRUCTION_POINTER_PROTOCOL_VERSION = 1;
    constexpr int VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION = 1;

    HRESULT VisionHotReloadError(json &body, const char *code, const std::string &message, HRESULT status)
    {
        body["visionErrorCode"] = code;
        body["message"] = message;
        std::ostringstream hresult;
        hresult << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << uint32_t(status);
        body["hresult"] = hresult.str();
        return status;
    }

    HRESULT VisionInstructionControlError(json &body, const std::string &code, const std::string &message, HRESULT status)
    {
        body["visionErrorCode"] = code;
        body["message"] = message;
        std::ostringstream hresult;
        hresult << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << uint32_t(status);
        body["hresult"] = hresult.str();
        return status;
    }

    std::string HResultText(HRESULT status)
    {
        std::ostringstream hresult;
        hresult << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << uint32_t(status);
        return hresult.str();
    }

    const char *RewindSafetyText(IDebugger::RewindSafety safety)
    {
        switch (safety)
        {
            case IDebugger::RewindSafety::Safe:
                return "safe";
            case IDebugger::RewindSafety::Unsafe:
                return "unsafe";
            default:
                return "unknown";
        }
    }

    json FrameIdentityJson(const IDebugger::RewindFrameIdentity &identity)
    {
        return json{
            {"stopId", identity.stopId},
            {"threadId", int(identity.threadId)},
            {"frameId", int(identity.frameId)},
            {"moduleMvid", identity.moduleMvid},
            {"methodToken", identity.methodToken},
            {"functionVersion", identity.functionVersion},
            {"ilOffset", identity.ilOffset}};
    }

    bool TryParseFrameIdentity(const json &value, IDebugger::RewindFrameIdentity &identity)
    {
        if (!value.is_object())
            return false;

        const char *stringFields[] = {"stopId", "moduleMvid"};
        const char *integerFields[] = {"threadId", "frameId", "methodToken", "functionVersion", "ilOffset"};
        for (const char *name : stringFields)
        {
            auto field = value.find(name);
            if (field == value.end() || !field->is_string() || field->get<std::string>().empty())
                return false;
        }
        for (const char *name : integerFields)
        {
            auto field = value.find(name);
            if (field == value.end() || !field->is_number_integer())
                return false;
        }

        const int threadId = value.at("threadId").get<int>();
        const int frameId = value.at("frameId").get<int>();
        const int64_t methodToken = value.at("methodToken").get<int64_t>();
        const int64_t functionVersion = value.at("functionVersion").get<int64_t>();
        const int64_t ilOffset = value.at("ilOffset").get<int64_t>();
        if (threadId <= 0 || frameId < 0 ||
            methodToken <= 0 || methodToken > std::numeric_limits<uint32_t>::max() ||
            functionVersion <= 0 || functionVersion > std::numeric_limits<ULONG32>::max() ||
            ilOffset < 0 || ilOffset > std::numeric_limits<ULONG32>::max())
        {
            return false;
        }

        identity.stopId = value.at("stopId").get<std::string>();
        identity.threadId = ThreadId(threadId);
        identity.frameId = FrameId(frameId);
        identity.moduleMvid = value.at("moduleMvid").get<std::string>();
        identity.methodToken = uint32_t(methodToken);
        identity.functionVersion = ULONG32(functionVersion);
        identity.ilOffset = ULONG32(ilOffset);
        return true;
    }

    bool IsReadableFile(const std::string &path)
    {
        std::ifstream stream(path, std::ios::in | std::ios::binary);
        return stream.good();
    }
} // unnamed namespace

void to_json(json &j, const Source &s) {
    j = json{{"name", s.name},
             {"path", s.path}};
}

void to_json(json &j, const Breakpoint &b) {
    j = json{
        {"id",       b.id},
        {"line",     b.line},
        {"verified", b.verified}};
    if (!b.message.empty())
        j["message"] = b.message;
    if (b.verified) {
        j["endLine"] = b.endLine;
        if (!b.source.IsNull())
            j["source"] = b.source;
    }
}

void to_json(json &j, const StackFrame &f) {
    j = json{
        {"id",        int(f.id)},
        {"name",      f.methodName},
        {"line",      f.line},
        {"column",    f.column},
        {"endLine",   f.endLine},
        {"endColumn", f.endColumn},
        {"moduleId",  f.moduleId}};
    if (!f.source.IsNull())
        j["source"] = f.source;
}

void to_json(json &j, const Thread &t) {
    j = json{{"id",   int(t.id)},
             {"name", t.name}};
          // {"running", t.running}
}

void to_json(json &j, const Scope &s) {
    j = json{
        {"name",               s.name},
        {"variablesReference", s.variablesReference},
        {"expensive",          false}};

    if (s.variablesReference > 0)
    {
        j["namedVariables"] = s.namedVariables;
        // j["indexedVariables"] = s.indexedVariables;
    }
}

void to_json(json &j, const Variable &v) {
    j = json{
        {"name",               v.name},
        {"value",              v.value},
        {"type",               v.type},
        {"evaluateName",       v.evaluateName},
        {"variablesReference", v.variablesReference}};

    if (v.variablesReference > 0)
    {
        j["namedVariables"] = v.namedVariables;
        // j["indexedVariables"] = v.indexedVariables;
    }
}

static json FormJsonForExceptionDetails(const ExceptionDetails &details)
{
    json result{{"typeName",             details.typeName},
                {"fullTypeName",         details.fullTypeName},
                {"evaluateName",         details.evaluateName},
                {"stackTrace",           details.stackTrace},
                {"formattedDescription", details.formattedDescription},
                {"source",               details.source}};

    if (!details.message.empty())
        result["message"] = details.message;

    if (details.innerException)
    {
        // Note, VSCode protocol have "innerException" field as array, but in real we don't have array with inner exceptions here,
        // since exception object have only one exeption object reference in InnerException field.
        json arr = json::array();
        arr.push_back(FormJsonForExceptionDetails(*details.innerException.get()));
        result["innerException"] = arr;
    }

    return result;
}

void VSCodeProtocol::EmitContinuedEvent(ThreadId threadId)
{
    LogFuncEntry();

    json body;

    if (threadId)
        body["threadId"] = int(threadId);

    body["allThreadsContinued"] = true;
    EmitEvent("continued", body);
}

void VSCodeProtocol::EmitStoppedEvent(const StoppedEvent &event)
{
    LogFuncEntry();

    json body;

    switch(event.reason)
    {
        case StopStep:
            body["reason"] = "step";
            break;
        case StopBreakpoint:
            body["reason"] = "breakpoint";
            break;
        case StopException:
            body["reason"] = "exception";
            break;
        case StopPause:
            body["reason"] = "pause";
            break;
        case StopEntry:
            body["reason"] = "entry";
            break;
    }

    // Note, `description` not in use at this moment, provide `reason` only.

    if (!event.text.empty())
        body["text"] = event.text;

    body["threadId"] = int(event.threadId);
    body["allThreadsStopped"] = event.allThreadsStopped;

    // vsdbg shows additional info, but it is not a part of the protocol
    // body["line"] = event.frame.line;
    // body["column"] = event.frame.column;

    // body["source"] = event.frame.source;

    EmitEvent("stopped", body);
}

void VSCodeProtocol::EmitVisionActiveFrameRemappedEvent(const ActiveFrameRemapEvent &event)
{
    json body = {
        {"protocolVersion", VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION},
        {"targetId", event.targetId},
        {"invocationId", event.invocationId},
        {"moduleMvid", event.moduleMvid},
        {"methodToken", event.methodToken},
        {"oldFunctionVersion", event.oldFunctionVersion},
        {"newFunctionVersion", event.newFunctionVersion},
        {"targetIlOffset", event.targetIlOffset},
        {"source", event.source.IsNull() ? json(nullptr) : json(event.source)},
        {"line", event.line}
    };
    EmitEvent("visionActiveFrameRemapped", body);
}

void VSCodeProtocol::EmitExitedEvent(const ExitedEvent &event)
{
    LogFuncEntry();
    json body;
    body["exitCode"] = event.exitCode;
    EmitEvent("exited", body);
}

void VSCodeProtocol::EmitTerminatedEvent()
{
    LogFuncEntry();
    EmitEvent("terminated", json::object());
}

void VSCodeProtocol::EmitThreadEvent(const ThreadEvent &event)
{
    LogFuncEntry();
    json body;

    switch(event.reason)
    {
        case ManagedThreadStarted:
            body["reason"] = "started";
            break;
        case ManagedThreadExited:
            body["reason"] = "exited";
            break;
        default:
            return;
    }

    body["threadId"] = int(event.threadId);

    EmitEvent("thread", body);
}

void VSCodeProtocol::EmitModuleEvent(const ModuleEvent &event)
{
    LogFuncEntry();
    json body;

    switch(event.reason)
    {
        case ModuleNew:
            body["reason"] = "new";
            break;
        case ModuleChanged:
            body["reason"] = "changed";
            break;
        case ModuleRemoved:
            body["reason"] = "removed";
            break;
    }

    json &module = body["module"];
    module["id"] = event.module.id;
    module["name"] = event.module.name;
    module["path"] = event.module.path;

    if (event.reason != ModuleRemoved)
    {
        switch(event.module.symbolStatus)
        {
            case SymbolsSkipped:
                module["symbolStatus"] = "Skipped loading symbols.";
                break;
            case SymbolsLoaded:
                module["symbolStatus"] = "Symbols loaded.";
                break;
            case SymbolsNotFound:
                module["symbolStatus"] = "Symbols not found.";
                break;
        }
    }

    EmitEvent("module", body);
}


namespace
{
    // Rules to escape characters in strings, in JSON.
    struct JSON_escape_rules
    {
       static const char forbidden_chars[];
       static const string_view subst_chars[];
       constexpr static const char escape_char = '\\';
    };

    // Allocate static memory for strings declared above.
    const char JSON_escape_rules::forbidden_chars[] =
    "\"\\"
    "\000\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017"
    "\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037";

    const string_view JSON_escape_rules::subst_chars[] = {
        "\\\"", "\\\\",
        "\\u0000", "\\u0001", "\\u0002", "\\u0003", "\\u0004", "\\u0005", "\\u0006", "\\u0007",
        "\\b", "\\t", "\\n", "\\u000b", "\\f", "\\r", "\\u000e", "\\u000f",
        "\\u0010", "\\u0011", "\\u0012", "\\u0013", "\\u0014", "\\u0015", "\\u0016", "\\u0017",
        "\\u0018", "\\u0019", "\\u001a", "\\u001b", "\\u001c", "\\u001d", "\\u001e", "\\u001f"
    };

    // This function serializes "OutputEvent" to specified output stream and used for two
    // purposes: to compute output size, and to perform the output directly.
    template <typename T1>
    void serialize_output(std::ostream& stream, uint64_t counter, string_view name, T1& text, Source& source)
    {
        stream << "{\"seq\":" << counter 
            << ", \"event\":\"output\",\"type\":\"event\",\"body\":{\"category\":\"" << name
            << "\",\"output\":\"" << text << "\"";

        if (!source.IsNull())
        {
            // "source":{"name":"Program.cs","path":"/path/Program.cs"}
            EscapedString<JSON_escape_rules> escaped_source_path(source.path);
            stream << ",\"source\":{\"name\":\"" << source.name << "\",\"path\":\"" << escaped_source_path << "\"}";
        }

        stream <<  "}}";

        stream.flush();
    };
}

void VSCodeProtocol::EmitOutputEvent(OutputCategory category, string_view output, string_view, DWORD threadId)
{
    LogFuncEntry();

    static const string_view categories[] = {"console", "stdout", "stderr"};

    // determine "category name"
    assert(category == OutputConsole || category == OutputStdOut || category == OutputStdErr);
    const string_view& name = categories[category];

    EscapedString<JSON_escape_rules> escaped_text(output);

    std::lock_guard<std::mutex> lock(m_outMutex);

    Source source;
    int totalFrames = 0;
    std::vector<StackFrame> stackFrames;
    if (threadId && SUCCEEDED(m_sharedDebugger->GetStackTrace(ThreadId(threadId), FrameLevel(0), 0, stackFrames, totalFrames)))
    {
        // Find first frame with source file data (code with PDB/user code).
        for (const StackFrame& stackFrame : stackFrames)
        {
            if (!stackFrame.source.IsNull())
            {
                source = stackFrame.source;
                break;
            }
        }
    }

    // compute size of headers without text (text could be huge, no reason parse it for size, that we already know)
    CountingStream count;
    serialize_output(count, m_seqCounter, name, "", source);

    // compute total size of headers + text
    auto const total_size = count.size() + escaped_text.size();

    // perform output
    cout << CONTENT_LENGTH << total_size << TWO_CRLF;
    serialize_output(cout, m_seqCounter, name, escaped_text, source);

    ++m_seqCounter;
}

void VSCodeProtocol::EmitBreakpointEvent(const BreakpointEvent &event)
{
    LogFuncEntry();
    json body;

    switch(event.reason)
    {
        case BreakpointNew:
            body["reason"] = "new";
            break;
        case BreakpointChanged:
            body["reason"] = "changed";
            break;
        case BreakpointRemoved:
            body["reason"] = "removed";
            break;
    }

    body["breakpoint"] = event.breakpoint;

    EmitEvent("breakpoint", body);
}

void VSCodeProtocol::EmitInitializedEvent()
{
    LogFuncEntry();
    EmitEvent("initialized", json::object());
}

void VSCodeProtocol::EmitExecEvent(PID pid, const std::string& argv0)
{
    json body;

    body["name"] = argv0;
    body["systemProcessId"] = PID::ScalarType(pid);
    body["isLocalProcess"] = true;
    body["startMethod"] = "launch";

    EmitEvent("process", body);
}

static void AddCapabilitiesTo(json &capabilities)
{
    capabilities["supportsConfigurationDoneRequest"] = true;
    capabilities["supportsFunctionBreakpoints"] = true;
    capabilities["supportsConditionalBreakpoints"] = true;
    capabilities["supportTerminateDebuggee"] = true;
    capabilities["supportsSetVariable"] = true;
    capabilities["supportsSetExpression"] = true;
    capabilities["supportsTerminateRequest"] = true;
    capabilities["supportsCancelRequest"] = true;
    capabilities["supportsVisionInstructionPointerControl"] = true;
    capabilities["visionInstructionPointerProtocolVersion"] = VISION_INSTRUCTION_POINTER_PROTOCOL_VERSION;
#ifdef EnC_SUPPORTED
    capabilities["supportsVisionActiveFrameRemap"] = true;
    capabilities["visionActiveFrameRemapProtocolVersion"] = VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION;
#endif

    capabilities["supportsExceptionInfoRequest"] = true;
    capabilities["supportsExceptionFilterOptions"] = true;
    json excFilters = json::array();
    for (const auto &entry : g_VSCodeFilters)
    {
        json filter{{"filter", entry.first},
                    {"label",  entry.first}};
        excFilters.push_back(filter);
    }
    capabilities["exceptionBreakpointFilters"] = excFilters;
    capabilities["supportsExceptionOptions"] = false; // TODO add implementation
#ifdef EnC_SUPPORTED
    capabilities["supportsVisionHotReload"] = true;
    capabilities["visionHotReloadProtocolVersion"] = VISION_HOT_RELOAD_PROTOCOL_VERSION;
#endif
}

void VSCodeProtocol::EmitCapabilitiesEvent()
{
    LogFuncEntry();

    json body = json::object();
    json capabilities = json::object();

    AddCapabilitiesTo(capabilities);

    body["capabilities"] = capabilities;

    EmitEvent("capabilities", body);
}

void VSCodeProtocol::Cleanup()
{

}

// Caller must care about m_outMutex.
void VSCodeProtocol::EmitMessage(nlohmann::json &message, std::string &output)
{
    message["seq"] = m_seqCounter;
    ++m_seqCounter;
    output = message.dump();
    cout << CONTENT_LENGTH << output.size() << TWO_CRLF << output;
    cout.flush();
}

void VSCodeProtocol::EmitMessageWithLog(const std::string &message_prefix, nlohmann::json &message)
{
    std::lock_guard<std::mutex> lock(m_outMutex);
    std::string output;
    EmitMessage(message, output);
    Log(message_prefix, output);
}

void VSCodeProtocol::EmitEvent(const std::string &name, const nlohmann::json &body)
{
    json message;
    message["type"] = "event";
    message["event"] = name;
    message["body"] = body;
    EmitMessageWithLog(LOG_EVENT, message);
}

static HRESULT HandleCommand(std::shared_ptr<IDebugger> &sharedDebugger, std::string &fileExec, std::vector<std::string> &execArgs,
                             const std::string &command, const json &arguments, json &body)
{
    typedef std::function<HRESULT(const json &arguments, json &body)> CommandCallback;
    static std::unordered_map<std::string, CommandCallback> commands {
    { "initialize", [&](const json &arguments, json &body){
        sharedDebugger->Initialize();

        AddCapabilitiesTo(body);

        return S_OK;
    } },
    { "setExceptionBreakpoints", [&](const json &arguments, json &body) {
        std::vector<std::string> filters = arguments.value("filters", std::vector<std::string>());
        std::vector<std::map<std::string, std::string>> filterOptions = arguments.value("filterOptions", std::vector<std::map<std::string, std::string>>());

        // https://microsoft.github.io/debug-adapter-protocol/specification#Requests_SetExceptionBreakpoints
        // The 'filter' and 'filterOptions' sets are additive.
        // Response to ‘setExceptionBreakpoints’ request:
        // ... The Breakpoint objects are in the same order as the elements of the ‘filters’, ‘filterOptions’, ‘exceptionOptions’ arrays given as arguments.
        std::vector<ExceptionBreakpoint> exceptionBreakpoints;

        for (auto &entry : filters)
        {
            auto findFilter = g_VSCodeFilters.find(entry);
            if (findFilter == g_VSCodeFilters.end())
                return E_INVALIDARG;
            // in case of VSCode protocol, we can't setup categoryHint during breakpoint setup, since this protocol don't provide such information
            exceptionBreakpoints.emplace_back(ExceptionCategory::ANY, findFilter->second);
        }

        for (auto &entry : filterOptions)
        {
            auto findId = entry.find("filterId");
            if (findId == entry.end() || findId->second.empty())
                return E_INVALIDARG;

            auto findFilter = g_VSCodeFilters.find(findId->second);
            if (findFilter == g_VSCodeFilters.end())
                return E_INVALIDARG;
            // in case of VSCode protocol, we can't setup categoryHint during breakpoint setup, since this protocol don't provide such information
            exceptionBreakpoints.emplace_back(ExceptionCategory::ANY, findFilter->second);

            auto findCondition = entry.find("condition");
            if (findCondition == entry.end() || findCondition->second.empty())
                continue;

            if (findCondition->second[0] == '!')
            {
                if (findCondition->second.size() == 1)
                    continue;

                findCondition->second[0] = ' ';
                exceptionBreakpoints.back().negativeCondition = true;
            }

            std::replace(findCondition->second.begin(), findCondition->second.end(), ',', ' ');
            std::stringstream ss(findCondition->second);
            std::istream_iterator<std::string> begin(ss);
            std::istream_iterator<std::string> end;
            exceptionBreakpoints.back().condition = std::unordered_set<std::string>(begin, end);
        }

        HRESULT Status;
        std::vector<Breakpoint> breakpoints;
        IfFailRet(sharedDebugger->SetExceptionBreakpoints(exceptionBreakpoints, breakpoints));

        // TODO form body with breakpoints (optional output, MS vsdbg don't provide it for VSCode IDE now)
        // body["breakpoints"] = breakpoints;

        return S_OK;
    } },
    { "configurationDone", [&](const json &arguments, json &body){
        return sharedDebugger->ConfigurationDone();
    } },
    { "exceptionInfo", [&](const json &arguments, json &body) {
        HRESULT Status;
        ThreadId threadId{int(arguments.at("threadId"))};
        ExceptionInfo exceptionInfo;
        IfFailRet(sharedDebugger->GetExceptionInfo(threadId, exceptionInfo));

        body["exceptionId"] = exceptionInfo.exceptionId;
        body["description"] = exceptionInfo.description;
        body["breakMode"] = exceptionInfo.breakMode;
        body["details"] = FormJsonForExceptionDetails(exceptionInfo.details);
        return S_OK;
    } },
    { "setBreakpoints", [&](const json &arguments, json &body){
        HRESULT Status;

        std::vector<LineBreakpoint> lineBreakpoints;
        for (auto &b : arguments.at("breakpoints"))
            lineBreakpoints.emplace_back(std::string(), b.at("line"), b.value("condition", std::string()));

        std::vector<Breakpoint> breakpoints;
        IfFailRet(sharedDebugger->SetLineBreakpoints(arguments.at("source").at("path"), lineBreakpoints, breakpoints));

        body["breakpoints"] = breakpoints;

        return S_OK;
    } },
    { "launch", [&](const json &arguments, json &body){
        auto cwdIt = arguments.find("cwd");
        const std::string cwd(cwdIt != arguments.end() ? cwdIt.value().get<std::string>() : std::string{});
        std::map<std::string, std::string> env;
        try
        {
            env = arguments.at("env").get<std::map<std::string, std::string> >();
        }
        catch (std::exception &ex)
        {
            LOGI("exception '%s'", ex.what());
            // If we catch inconsistent state on the interrupted reading
            env.clear();
        }

        sharedDebugger->SetJustMyCode(arguments.value("justMyCode", true)); // MS vsdbg have "justMyCode" enabled by default.
        sharedDebugger->SetStepFiltering(arguments.value("enableStepFiltering", true)); // MS vsdbg have "enableStepFiltering" enabled by default.

        if (arguments.value("enableHotReload", false))
        {
#ifdef EnC_SUPPORTED
            HRESULT Status;
            IfFailRet(sharedDebugger->SetHotReload(true));
#else
            return VisionHotReloadError(
                body,
                "vision_hot_reload_unsupported",
                "Vision Hot Reload is not supported by this platform build.",
                E_NOTIMPL);
#endif
        }

        if (!fileExec.empty())
            return sharedDebugger->Launch(fileExec, execArgs, env, cwd, arguments.value("stopAtEntry", false));

        std::string program = arguments.at("program").get<std::string>();
        std::vector<std::string> args = arguments.value("args", std::vector<std::string>());

        std::string dllSuffix = ".dll";
        if (program.size() >= dllSuffix.size() && program.compare(program.size()-dllSuffix.size(), dllSuffix.size(), dllSuffix) == 0)
        {
            args.insert(args.begin(), program);
            return sharedDebugger->Launch("dotnet", args, env, cwd, arguments.value("stopAtEntry", false));
        }
        else
        {
            // If we're not being asked to launch a dll, assume whatever we're given is an executable
            return sharedDebugger->Launch(program, args, env, cwd, arguments.value("stopAtEntry", false));
        }
    } },
    { "visionApplyHotReload", [&](const json &arguments, json &body){
#ifndef EnC_SUPPORTED
        return VisionHotReloadError(
            body,
            "vision_hot_reload_unsupported",
            "Vision Hot Reload is not supported by this platform build.",
            E_NOTIMPL);
#else
        const int protocolVersion = arguments.value("protocolVersion", 0);
        if (protocolVersion != VISION_HOT_RELOAD_PROTOCOL_VERSION)
            return VisionHotReloadError(
                body,
                "vision_hot_reload_invalid_request",
                "Unsupported Vision Hot Reload protocol version.",
                E_INVALIDARG);

        const char *required[] = {
            "moduleName", "moduleMvid", "metadataDeltaPath", "ilDeltaPath", "pdbDeltaPath", "lineUpdatesPath"
        };
        for (const char *name : required)
        {
            auto value = arguments.find(name);
            if (value == arguments.end() || !value->is_string() || value->get<std::string>().empty())
                return VisionHotReloadError(
                    body,
                    "vision_hot_reload_invalid_request",
                    std::string("Missing or invalid required argument '") + name + "'.",
                    E_INVALIDARG);
        }

        if (sharedDebugger->IsAttachSession())
            return VisionHotReloadError(
                body,
                "vision_hot_reload_attach_unsupported",
                "Vision Hot Reload is supported for launch sessions only.",
                CORDBG_E_CANNOT_BE_ON_ATTACH);

        if (!sharedDebugger->IsHotReload())
            return VisionHotReloadError(
                body,
                "vision_hot_reload_not_enabled",
                "Vision Hot Reload was not enabled by the launch request.",
                E_ACCESSDENIED);

        const std::string metadataDelta = arguments.at("metadataDeltaPath").get<std::string>();
        const std::string ilDelta = arguments.at("ilDeltaPath").get<std::string>();
        const std::string pdbDelta = arguments.at("pdbDeltaPath").get<std::string>();
        const std::string lineUpdates = arguments.at("lineUpdatesPath").get<std::string>();
        auto updatedMethods = arguments.find("updatedMethodTokens");
        if (updatedMethods == arguments.end() || !updatedMethods->is_array() || updatedMethods->empty())
            return VisionHotReloadError(
                body,
                "vision_hot_reload_invalid_request",
                "updatedMethodTokens must contain at least one MethodDef token.",
                E_INVALIDARG);
        std::vector<uint32_t> updatedMethodTokens;
        for (const auto &token : *updatedMethods)
        {
            if (!token.is_number_unsigned() && !token.is_number_integer())
                return VisionHotReloadError(body, "vision_hot_reload_invalid_request", "updatedMethodTokens contains an invalid token.", E_INVALIDARG);
            const int64_t value = token.get<int64_t>();
            if (value <= 0 || value > std::numeric_limits<uint32_t>::max())
                return VisionHotReloadError(body, "vision_hot_reload_invalid_request", "updatedMethodTokens contains an invalid token.", E_INVALIDARG);
            updatedMethodTokens.push_back(uint32_t(value));
        }
        for (const auto &path : {metadataDelta, ilDelta, pdbDelta, lineUpdates})
        {
            if (!IsReadableFile(path))
                return VisionHotReloadError(
                    body,
                    "vision_hot_reload_invalid_request",
                    std::string("Delta artifact is missing or unreadable: ") + path,
                    COR_E_FILENOTFOUND);
        }

        std::vector<IDebugger::HotReloadMethodGeneration> methodGenerations;
        std::string failureStage;
        HRESULT Status = sharedDebugger->HotReloadApplyDeltas(
            arguments.at("moduleName").get<std::string>(),
            arguments.at("moduleMvid").get<std::string>(),
            updatedMethodTokens,
            metadataDelta,
            ilDelta,
            pdbDelta,
            lineUpdates,
            methodGenerations,
            failureStage);
        if (FAILED(Status))
        {
            HRESULT error = VisionHotReloadError(
                body,
                "vision_hot_reload_apply_failed",
                "The debugger failed to apply Hot Reload deltas. Verify the module name and delta artifacts.",
                Status);
            body["stage"] = failureStage.empty() ? "unknown" : failureStage;
            return error;
        }

        body["protocolVersion"] = VISION_HOT_RELOAD_PROTOCOL_VERSION;
        body["applied"] = true;
        body["moduleName"] = arguments.at("moduleName");
        body["moduleMvid"] = arguments.at("moduleMvid");
        body["methodGenerations"] = json::array();
        for (const auto &generation : methodGenerations)
        {
            body["methodGenerations"].push_back({
                {"methodToken", generation.methodToken},
                {"previousGeneration", generation.previousGeneration},
                {"appliedGeneration", generation.appliedGeneration}
            });
        }
        return S_OK;
#endif
    } },
    { "visionInspectFrameGeneration", [&](const json &arguments, json &body){
        if (arguments.value("protocolVersion", 0) != VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION)
            return VisionInstructionControlError(body, "vision_active_frame_remap_invalid_request", "Unsupported active-frame remap protocol version.", E_INVALIDARG);
        const int threadId = arguments.value("threadId", 0);
        const int frameId = arguments.value("frameId", -1);
        if (threadId <= 0 || frameId < 0)
            return VisionInstructionControlError(body, "vision_active_frame_remap_invalid_request", "threadId and frameId are required.", E_INVALIDARG);
        IDebugger::FrameGenerationEvidence evidence;
        HRESULT Status = sharedDebugger->InspectFrameGeneration(ThreadId(threadId), FrameId(frameId), evidence);
        if (FAILED(Status))
            return VisionInstructionControlError(body, "vision_active_frame_inspection_failed", "The active frame generation could not be inspected.", Status);
        body["protocolVersion"] = VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION;
        body["frameIdentity"] = FrameIdentityJson(evidence.frame);
        body["latestGeneration"] = evidence.latestGeneration;
        body["invocationId"] = evidence.invocationId;
        return S_OK;
    } },
    { "visionResolveActiveFrameRemapTarget", [&](const json &arguments, json &body){
        if (arguments.value("protocolVersion", 0) != VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION)
            return VisionInstructionControlError(body, "vision_active_frame_remap_invalid_request", "Unsupported active-frame remap protocol version.", E_INVALIDARG);
        const int threadId = arguments.value("threadId", 0);
        const int frameId = arguments.value("frameId", -1);
        const int line = arguments.value("line", 0);
        const int64_t methodToken = arguments.value("methodToken", int64_t(0));
        const int64_t appliedGeneration = arguments.value("appliedGeneration", int64_t(0));
        const std::string sourceFile = arguments.value("sourceFile", std::string());
        const std::string moduleMvid = arguments.value("moduleMvid", std::string());
        if (threadId <= 0 || frameId < 0 || line <= 0 || methodToken <= 0 || appliedGeneration <= 1 || sourceFile.empty() || moduleMvid.empty())
            return VisionInstructionControlError(body, "vision_active_frame_remap_invalid_request", "A complete active-frame remap target is required.", E_INVALIDARG);
        IDebugger::ActiveFrameRemapTarget target;
        HRESULT Status = sharedDebugger->ResolveActiveFrameRemapTarget(
            ThreadId(threadId), FrameId(frameId), sourceFile, line, moduleMvid,
            uint32_t(methodToken), ULONG32(appliedGeneration), target);
        if (FAILED(Status))
            return VisionInstructionControlError(body, "vision_active_frame_remap_resolve_failed", "The updated frame target could not be resolved.", Status);
        body["protocolVersion"] = VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION;
        body["status"] = RewindSafetyText(target.safety);
        body["reasonCode"] = target.reasonCode;
        body["reason"] = target.reason;
        body["frameIdentity"] = FrameIdentityJson(target.frame);
        body["targetId"] = target.targetId.empty() ? json(nullptr) : json(target.targetId);
        body["targetIlOffset"] = target.targetIlOffset;
        body["resolvedLine"] = target.resolvedLine > 0 ? json(target.resolvedLine) : json(nullptr);
        body["source"] = target.source.IsNull() ? json(nullptr) : json(target.source);
        body["appliedGeneration"] = target.appliedGeneration;
        body["invocationId"] = target.invocationId;
        return S_OK;
    } },
    { "visionArmActiveFrameRemap", [&](const json &arguments, json &body){
        if (arguments.value("protocolVersion", 0) != VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION)
            return VisionInstructionControlError(body, "vision_active_frame_remap_invalid_request", "Unsupported active-frame remap protocol version.", E_INVALIDARG);
        auto targetId = arguments.find("targetId");
        auto expectedFrame = arguments.find("expectedFrameIdentity");
        IDebugger::RewindFrameIdentity identity;
        if (targetId == arguments.end() || !targetId->is_string() || targetId->get<std::string>().empty() ||
            expectedFrame == arguments.end() || !TryParseFrameIdentity(*expectedFrame, identity))
            return VisionInstructionControlError(body, "vision_active_frame_remap_invalid_request", "targetId and expectedFrameIdentity are required.", E_INVALIDARG);
        HRESULT Status = sharedDebugger->ArmActiveFrameRemap(targetId->get<std::string>(), identity);
        if (FAILED(Status))
            return VisionInstructionControlError(body, "vision_active_frame_remap_arm_failed", "The remap target is missing, expired, or stale.", Status);
        body["protocolVersion"] = VISION_ACTIVE_FRAME_REMAP_PROTOCOL_VERSION;
        body["armed"] = true;
        body["targetId"] = *targetId;
        return S_OK;
    } },
    { "visionResolveRewindTarget", [&](const json &arguments, json &body){
        const int protocolVersion = arguments.value("protocolVersion", 0);
        if (protocolVersion != VISION_INSTRUCTION_POINTER_PROTOCOL_VERSION)
            return VisionInstructionControlError(
                body,
                "vision_instruction_control_invalid_request",
                "Unsupported Vision instruction pointer protocol version.",
                E_INVALIDARG);

        auto sourceFile = arguments.find("sourceFile");
        auto threadId = arguments.find("threadId");
        auto frameId = arguments.find("frameId");
        auto line = arguments.find("line");
        if (sourceFile == arguments.end() || !sourceFile->is_string() || sourceFile->get<std::string>().empty() ||
            threadId == arguments.end() || !threadId->is_number_integer() ||
            frameId == arguments.end() || !frameId->is_number_integer() ||
            line == arguments.end() || !line->is_number_integer() ||
            threadId->get<int>() <= 0 || frameId->get<int>() < 0 || line->get<int>() <= 0)
        {
            return VisionInstructionControlError(
                body,
                "vision_instruction_control_invalid_request",
                "Required arguments are protocolVersion, threadId, frameId, sourceFile, and line.",
                E_INVALIDARG);
        }

        IDebugger::RewindTarget target;
        HRESULT Status = sharedDebugger->ResolveRewindTarget(
            ThreadId(threadId->get<int>()),
            FrameId(frameId->get<int>()),
            sourceFile->get<std::string>(),
            line->get<int>(),
            target);
        if (FAILED(Status))
        {
            const bool notStopped = Status == CORDBG_E_PROCESS_NOT_SYNCHRONIZED;
            return VisionInstructionControlError(
                body,
                notStopped ? "vision_instruction_control_not_stopped" : "vision_instruction_control_resolve_failed",
                notStopped
                    ? "The debuggee must be stopped on the requested top managed frame."
                    : "The debugger could not inspect the requested frame.",
                Status);
        }

        body["protocolVersion"] = VISION_INSTRUCTION_POINTER_PROTOCOL_VERSION;
        body["status"] = RewindSafetyText(target.safety);
        body["reasonCode"] = target.reasonCode;
        body["reason"] = target.reason;
        body["canSetIpHResult"] = HResultText(target.canSetIpHResult);
        body["frameIdentity"] = FrameIdentityJson(target.frame);
        body["targetId"] = target.targetId.empty() ? json(nullptr) : json(target.targetId);
        body["requestedLine"] = target.requestedLine;
        body["resolvedLine"] = target.resolvedLine > 0 ? json(target.resolvedLine) : json(nullptr);
        body["resolvedColumn"] = target.resolvedColumn > 0 ? json(target.resolvedColumn) : json(nullptr);
        body["targetIlOffset"] = target.targetIlOffset;
        body["expiresInMs"] = target.expiresInMs > 0 ? json(target.expiresInMs) : json(nullptr);
        body["source"] = target.source.IsNull() ? json(nullptr) : json(target.source);
        return S_OK;
    } },
    { "visionSetInstructionPointer", [&](const json &arguments, json &body){
        const int protocolVersion = arguments.value("protocolVersion", 0);
        if (protocolVersion != VISION_INSTRUCTION_POINTER_PROTOCOL_VERSION)
            return VisionInstructionControlError(
                body,
                "vision_instruction_control_invalid_request",
                "Unsupported Vision instruction pointer protocol version.",
                E_INVALIDARG);

        auto targetId = arguments.find("rewindTargetId");
        auto expectedFrame = arguments.find("expectedFrameIdentity");
        IDebugger::RewindFrameIdentity identity;
        if (targetId == arguments.end() || !targetId->is_string() || targetId->get<std::string>().empty() ||
            expectedFrame == arguments.end() || !TryParseFrameIdentity(*expectedFrame, identity))
        {
            return VisionInstructionControlError(
                body,
                "vision_instruction_control_invalid_request",
                "Required arguments are protocolVersion, rewindTargetId, and a complete expectedFrameIdentity.",
                E_INVALIDARG);
        }

        IDebugger::InstructionPointerResult result;
        HRESULT Status = sharedDebugger->SetInstructionPointer(targetId->get<std::string>(), identity, result);
        if (FAILED(Status))
        {
            return VisionInstructionControlError(
                body,
                result.reasonCode.empty() ? "vision_instruction_control_set_failed" : result.reasonCode,
                result.reason.empty() ? "The debugger refused to move the instruction pointer." : result.reason,
                Status);
        }

        body["protocolVersion"] = VISION_INSTRUCTION_POINTER_PROTOCOL_VERSION;
        body["moved"] = result.moved;
        body["handlesInvalidated"] = result.handlesInvalidated;
        body["canSetIpHResult"] = HResultText(result.canSetIpHResult);
        body["setIpHResult"] = HResultText(result.setIpHResult);
        body["previousFrameIdentity"] = FrameIdentityJson(result.previousFrame);
        if (!result.currentFrame.stopId.empty())
        {
            body["frameIdentity"] = FrameIdentityJson(result.currentFrame);
            body["stoppedFrame"] = result.stoppedFrame;
        }
        else
        {
            body["frameIdentity"] = nullptr;
            body["stoppedFrame"] = nullptr;
        }
        body["warnings"] = result.warnings;
        return S_OK;
    } },
    { "threads", [&](const json &arguments, json &body){
        HRESULT Status;
        std::vector<Thread> threads;
        IfFailRet(sharedDebugger->GetThreads(threads));

        body["threads"] = threads;

        return S_OK;
    } },
    { "disconnect", [&](const json &arguments, json &body){
        auto terminateArgIter = arguments.find("terminateDebuggee");
        IDebugger::DisconnectAction action;
        if (terminateArgIter == arguments.end())
            action = IDebugger::DisconnectAction::DisconnectDefault;
        else
            action = terminateArgIter.value().get<bool>() ? IDebugger::DisconnectAction::DisconnectTerminate : IDebugger::DisconnectAction::DisconnectDetach;

        sharedDebugger->Disconnect(action);

        return S_OK;
    } },
    { "terminate", [&](const json &arguments, json &body){
        sharedDebugger->Disconnect(IDebugger::DisconnectAction::DisconnectTerminate);
        return S_OK;
    } },
    { "stackTrace", [&](const json &arguments, json &body){
        HRESULT Status;

        int totalFrames = 0;
        ThreadId threadId{int(arguments.at("threadId"))};

        std::vector<StackFrame> stackFrames;
        IfFailRet(sharedDebugger->GetStackTrace(
            threadId,
            FrameLevel{arguments.value("startFrame", 0)},
            unsigned(arguments.value("levels", 0)),
            stackFrames,
            totalFrames
            ));

        body["stackFrames"] = stackFrames;
        body["totalFrames"] = totalFrames;

        return S_OK;
    } },
    { "continue", [&](const json &arguments, json &body){
        body["allThreadsContinued"] = true;

        ThreadId threadId{int(arguments.at("threadId"))};
        body["threadId"] = int(threadId);
        return sharedDebugger->Continue(threadId);
    } },
    { "pause", [&](const json &arguments, json &body){
        ThreadId threadId{int(arguments.at("threadId"))};
        body["threadId"] = int(threadId);
        return sharedDebugger->Pause(threadId, EventFormat::Default);
    } },
    { "next", [&](const json &arguments, json &body){
        return sharedDebugger->StepCommand(ThreadId{int(arguments.at("threadId"))}, IDebugger::StepType::STEP_OVER);
    } },
    { "stepIn", [&](const json &arguments, json &body){
        return sharedDebugger->StepCommand(ThreadId{int(arguments.at("threadId"))}, IDebugger::StepType::STEP_IN);
    } },
    { "stepOut", [&](const json &arguments, json &body){
        return sharedDebugger->StepCommand(ThreadId{int(arguments.at("threadId"))}, IDebugger::StepType::STEP_OUT);
    } },
    { "scopes", [&](const json &arguments, json &body){
        HRESULT Status;
        std::vector<Scope> scopes;
        FrameId frameId{int(arguments.at("frameId"))};
        IfFailRet(sharedDebugger->GetScopes(frameId, scopes));

        body["scopes"] = scopes;

        return S_OK;
    } },
    { "variables", [&](const json &arguments, json &body){
        HRESULT Status;
        std::string filterName = arguments.value("filter", "");
        VariablesFilter filter = VariablesBoth;
        if (filterName == "named")
            filter = VariablesNamed;
        else if (filterName == "indexed")
            filter = VariablesIndexed;

        std::vector<Variable> variables;
        IfFailRet(sharedDebugger->GetVariables(
            arguments.at("variablesReference"),
            filter,
            arguments.value("start", 0),
            arguments.value("count", 0),
            variables));

        body["variables"] = variables;

        return S_OK;
    } },
    { "evaluate", [&](const json &arguments, json &body){
        HRESULT Status;
        std::string expression = arguments.at("expression");
        FrameId frameId([&](){
            auto frameIdIter = arguments.find("frameId");
            if (frameIdIter == arguments.end())
            {
                ThreadId threadId = sharedDebugger->GetLastStoppedThreadId();
                return FrameId{threadId, FrameLevel{0}};
            }
            else {
                return FrameId{int(frameIdIter.value())};
            }
        }());

        // NOTE
        // VSCode don't support evaluation flags, we can't disable implicit function calls during evaluation.
        // https://github.com/OmniSharp/omnisharp-vscode/issues/3173
        Variable variable;
        std::string output;
        Status = sharedDebugger->Evaluate(frameId, expression, variable, output);
        if (FAILED(Status))
        {
            if (output.empty())
            {
                std::stringstream stream;
                stream << "error: 0x" << std::hex << Status;
                body["message"] = stream.str();
            }
            else
                body["message"] = output;

            return Status;
        }

        body["result"] = variable.value;
        body["type"] = variable.type;
        body["variablesReference"] = variable.variablesReference;
        if (variable.variablesReference > 0)
        {
            body["namedVariables"] = variable.namedVariables;
            // indexedVariables
        }
        return S_OK;
    } },
    { "setExpression", [&](const json &arguments, json &body){
        HRESULT Status;
        std::string expression = arguments.at("expression");
        std::string value = arguments.at("value");
        FrameId frameId([&](){
            auto frameIdIter = arguments.find("frameId");
            if (frameIdIter == arguments.end())
            {
                ThreadId threadId = sharedDebugger->GetLastStoppedThreadId();
                return FrameId{threadId, FrameLevel{0}};
            }
            else {
                return FrameId{int(frameIdIter.value())};
            }
        }());

        // NOTE
        // VSCode don't support evaluation flags, we can't disable implicit function calls during evaluation.
        // https://github.com/OmniSharp/omnisharp-vscode/issues/3173
        std::string output;
        Status = sharedDebugger->SetExpression(frameId, expression, defaultEvalFlags, value, output);
        if (FAILED(Status))
        {
            if (output.empty())
            {
                std::stringstream stream;
                stream << "error: 0x" << std::hex << Status;
                body["message"] = stream.str();
            }
            else
                body["message"] = output;

            return Status;
        }

        body["value"] = output;
        return S_OK;
    } },
    { "attach", [&](const json &arguments, json &body){
        int processId;

        const json &processIdArg = arguments.at("processId");
        if (processIdArg.is_string())
            processId = std::stoi(processIdArg.get<std::string>());
        else if (processIdArg.is_number())
            processId = processIdArg;
        else
            return E_INVALIDARG;

        return sharedDebugger->Attach(processId);
    } },
    { "setVariable", [&](const json &arguments, json &body) {
        HRESULT Status;

        std::string name = arguments.at("name");
        std::string value = arguments.at("value");
        int ref = arguments.at("variablesReference");

        std::string output;
        Status = sharedDebugger->SetVariable(name, value, ref, output);
        if (FAILED(Status))
        {
            body["message"] = output;
            return Status;
        }

        body["value"] = output;

        return S_OK;
    } },
    { "setFunctionBreakpoints", [&](const json &arguments, json &body) {
        HRESULT Status = S_OK;

        std::vector<FuncBreakpoint> funcBreakpoints;
        for (auto &b : arguments.at("breakpoints"))
        {
            std::string module("");
            std::string params("");
            std::string name = b.at("name");

            std::size_t i = name.find('!');

            if (i != std::string::npos)
            {
                module = std::string(name, 0, i);
                name.erase(0, i + 1);
            }

            i = name.find('(');
            if (i != std::string::npos)
            {
                std::size_t closeBrace = name.find(')');

                params = std::string(name, i, closeBrace - i + 1);
                name.erase(i, closeBrace);
            }

            funcBreakpoints.emplace_back(module, name, params, b.value("condition", std::string()));
        }

        std::vector<Breakpoint> breakpoints;
        IfFailRet(sharedDebugger->SetFuncBreakpoints(funcBreakpoints, breakpoints));

        body["breakpoints"] = breakpoints;

        return Status;
    } }
    };

    auto command_it = commands.find(command);
    if (command_it == commands.end())
    {
        return E_NOTIMPL;
    }

    return command_it->second(arguments, body);
}

static HRESULT HandleCommandJSON(std::shared_ptr<IDebugger> &sharedDebugger, std::string &fileExec, std::vector<std::string> &execArgs,
                                 const std::string &command, const json &arguments, json &body)
{
    try
    {
        return HandleCommand(sharedDebugger, fileExec, execArgs, command, arguments, body);
    }
    catch (nlohmann::detail::exception& ex)
    {
        LOGE("JSON error: %s", ex.what());
        body["message"] = std::string("can't parse: ") + ex.what();
    }

    return E_FAIL;
}

static std::string ReadData(std::istream& cin)
{
    // parse header (only content len) until empty line
    long content_len = -1;
    while (true)
    {
        std::string line;
        std::getline(cin, line);
        if (!cin.good())
        {
            if (cin.eof()) LOGI("EOF");
            else LOGE("input stream reading error");
            return {};
        }

        if (!line.empty() && line.back() == '\r')
                line.pop_back();

        if (line.empty())
        {
            if (content_len < 0)
            {
                LOGE("protocol error: no 'Content Length:' field!");
                return {};
            }
            break;         // header and content delimiter
        }

        LOGD("header: '%s'", line.c_str());

        if (line.size() > CONTENT_LENGTH.size()
            && std::equal(CONTENT_LENGTH.begin(), CONTENT_LENGTH.end(), line.begin()))
        {
            if (content_len >= 0)
                LOGW("protocol violation: duplicate '%s'", line.c_str());

            char *p;
            errno = 0;
            content_len = strtoul(&line[CONTENT_LENGTH.size()], &p, 10);
            if (errno == ERANGE || !(*p == 0 || isspace(*p)))
            {
                LOGE("protocol violation: '%s'", line.c_str());
                return {};
            }
        }
    }

    std::string result(content_len, 0);
    if (!cin.read(&result[0], content_len))
    {
        if (cin.eof()) LOGE("Unexpected EOF!");
        else LOGE("input stream reading error");
        return {};
    }

    return result;
}

void VSCodeProtocol::CommandsWorker()
{
    std::unique_lock<std::mutex> lockCommandsMutex(m_commandsMutex);

    while (true)
    {
        while (m_commandsQueue.empty())
        {
            // Note, during m_commandsCV.wait() (waiting for notify_one call with entry added into queue),
            // m_commandsMutex will be unlocked (see std::condition_variable for more info).
            m_commandsCV.wait(lockCommandsMutex);
        }

        CommandQueueEntry c = std::move(m_commandsQueue.front());
        m_commandsQueue.pop_front();
        lockCommandsMutex.unlock();

        // Check for ncdbg internal commands.
        if (c.command == "ncdbg_disconnect")
        {
            m_sharedDebugger->Disconnect();
            break;
        }

        json body = json::object();
        std::future<HRESULT> future = std::async(std::launch::async, [&](){
            return HandleCommandJSON(m_sharedDebugger, m_fileExec, m_execArgs, c.command, c.arguments, body);
        });
        HRESULT Status;
        // Note, CommandsWorker() loop should never hangs, but even in case some command execution is timed out,
        // this could be not critical issue. Let IDE decide.

        // MSVS debugger use config file, for Visual Studio 2022 Community Edition located at
        // C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\Profiles\CSharp.vssettings
        // Visual Studio have timeout setup for each type of requests, for example:
        // LocalsTimeout = 1000
        // LongEvalTimeout = 10000
        // NormalEvalTimeout = 5000
        // QuickwatchTimeout = 15000
        // SetValueTimeout = 10000
        // ...
        // we use max default timeout (15000), one timeout for all requests.

        // TODO add timeout configuration feature
        std::future_status timeoutStatus = future.wait_for(std::chrono::milliseconds(15000));
        if (timeoutStatus == std::future_status::timeout)
        {
            body["message"] = "Command execution timed out.";
            Status = COR_E_TIMEOUT;
        }
        else
            Status = future.get();

        if (SUCCEEDED(Status))
        {
            c.response["success"] = true;
            c.response["body"] = body;
        }
        else
        {
            if (body.find("message") == body.end())
            {
                std::ostringstream ss;
                ss << "Failed command '" << c.command << "' : "
                << "0x" << std::setw(8) << std::setfill('0') << std::hex << Status;
                c.response["message"] = ss.str();
            }
            else
                c.response["message"] = body["message"];

            c.response["success"] = false;
            if (body.find("visionErrorCode") != body.end())
                c.response["body"] = body;
        }

        EmitMessageWithLog(LOG_RESPONSE, c.response);

        // Post command action.
        if (g_syncCommandExecutionSet.find(c.command) != g_syncCommandExecutionSet.end())
            m_commandSyncCV.notify_one();

        if (c.command == "disconnect")
            break;
        // The Debug Adapter Protocol specifies that `InitializedEvent` occurs after the `InitializeRequest` has returned:
        // https://microsoft.github.io/debug-adapter-protocol/specification#arrow_left-initialized-event
        else if (c.command == "initialize" && SUCCEEDED(Status))
            EmitInitializedEvent();

        lockCommandsMutex.lock();
    }

    m_exit = true;
}

// Caller must care about m_commandsMutex.
std::list<VSCodeProtocol::CommandQueueEntry>::iterator VSCodeProtocol::CancelCommand(const std::list<VSCodeProtocol::CommandQueueEntry>::iterator &iter)
{
    iter->response["success"] = false;
    iter->response["message"] = std::string("Error processing '") + iter->command + std::string("' request. The operation was canceled.");
    EmitMessageWithLog(LOG_RESPONSE, iter->response);
    return m_commandsQueue.erase(iter);
}

void VSCodeProtocol::CommandLoop()
{
    std::thread commandsWorker{&VSCodeProtocol::CommandsWorker, this};

    m_exit = false;

    while (!m_exit)
    {
        std::string requestText = ReadData(cin);
        if (requestText.empty())
        {
            CommandQueueEntry queueEntry;
            queueEntry.command = "ncdbg_disconnect";
            std::lock_guard<std::mutex> guardCommandsMutex(m_commandsMutex);
            m_commandsQueue.clear();
            m_commandsQueue.emplace_back(std::move(queueEntry));
            m_commandsCV.notify_one(); // notify_one with lock
            break;
        }

        {
            std::lock_guard<std::mutex> lock(m_outMutex);
            Log(LOG_COMMAND, requestText);
        }

        struct bad_format : public std::invalid_argument
        {
            bad_format(const char *s) : invalid_argument(s) {}
        };

        CommandQueueEntry queueEntry;
        try
        {
            json request = json::parse(requestText);

            // Variable `resp' is used to construct response and assign it to `response'
            // variable in single step: `response' variable should always be in
            // consistent state (it must not have state when some fields is assigned and
            // some not assigned due to an exception) because `response' is used below
            // in exception handler.
            json resp;
            resp["type"] = "response";
            resp["request_seq"] = request.at("seq");
            queueEntry.response = resp;

            queueEntry.command = request.at("command");
            resp["command"] = queueEntry.command;
            queueEntry.response = resp;

            if (request["type"] != "request")
                throw bad_format("wrong request type!");

            auto argIter = request.find("arguments");
            queueEntry.arguments = (argIter == request.end() ? json::object() : argIter.value());

            // Pre command action.
            if (queueEntry.command == "initialize")
                EmitCapabilitiesEvent();
            else if (g_cancelCommandQueueSet.find(queueEntry.command) != g_cancelCommandQueueSet.end())
            {
                std::lock_guard<std::mutex> guardCommandsMutex(m_commandsMutex);
                m_sharedDebugger->CancelEvalRunning();

                for (auto iter = m_commandsQueue.begin(); iter != m_commandsQueue.end();)
                {
                    if (g_debuggerSetupCommandSet.find(iter->command) != g_debuggerSetupCommandSet.end())
                        ++iter;
                    else
                        iter = CancelCommand(iter);
                }
            }
            // Note, in case "cancel" this is command implementation itself.
            else if (queueEntry.command == "cancel")
            {
                auto requestId = queueEntry.arguments.at("requestId");
                std::unique_lock<std::mutex> lockCommandsMutex(m_commandsMutex);
                queueEntry.response["success"] = false;
                for (auto iter = m_commandsQueue.begin(); iter != m_commandsQueue.end(); ++iter)
                {
                    if (requestId != iter->response["request_seq"])
                        continue;

                    if (g_debuggerSetupCommandSet.find(iter->command) != g_debuggerSetupCommandSet.end())
                        break;

                    CancelCommand(iter);

                    queueEntry.response["success"] = true;
                    break;
                }
                lockCommandsMutex.unlock();

                if (!queueEntry.response["success"])
                    queueEntry.response["message"] = "CancelRequest is not supported for requestId.";

                EmitMessageWithLog(LOG_RESPONSE, queueEntry.response);
                continue;
            }

            std::unique_lock<std::mutex> lockCommandsMutex(m_commandsMutex);
            bool isCommandNeedSync = g_syncCommandExecutionSet.find(queueEntry.command) != g_syncCommandExecutionSet.end();
            m_commandsQueue.emplace_back(std::move(queueEntry));
            m_commandsCV.notify_one(); // notify_one with lock

            if (isCommandNeedSync)
                m_commandSyncCV.wait(lockCommandsMutex);

            continue;
        }
        catch (nlohmann::detail::exception& ex)
        {
            LOGE("JSON error: %s", ex.what());
            queueEntry.response["type"] = "response";
            queueEntry.response["success"] = false;
            queueEntry.response["message"] = std::string("can't parse: ") + ex.what();
        }
        catch (bad_format& ex)
        {
            LOGE("JSON error: %s", ex.what());
            queueEntry.response["type"] = "response";
            queueEntry.response["success"] = false;
            queueEntry.response["message"] = std::string("can't parse: ") + ex.what();
        }

        EmitMessageWithLog(LOG_RESPONSE, queueEntry.response);
    }

    commandsWorker.join();
}

void VSCodeProtocol::EngineLogging(const std::string &path)
{
    if (path.empty())
    {
        m_engineLogOutput = LogConsole;
    }
    else
    {
        m_engineLogOutput = LogFile;
        m_engineLog.open(path);
    }
}

// Caller must care about m_outMutex.
void VSCodeProtocol::Log(const std::string &prefix, const std::string &text)
{
    switch(m_engineLogOutput)
    {
        case LogNone:
            return;
        case LogFile:
            m_engineLog << prefix << text << std::endl;
            m_engineLog.flush();
            return;
        case LogConsole:
        {
            json response;
            response["type"] = "event";
            response["event"] = "output";
            response["body"] = json{
                {"category", "console"},
                {"output", prefix + text + "\n"}
            };
            std::string output;
            EmitMessage(response, output);
            return;
        }
    }
}

} // namespace netcoredbg
