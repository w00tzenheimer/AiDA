#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

class aida_plugin_t;

class settings_t
{
public:
    std::string api_provider;

    std::string gemini_api_key;
    std::string gemini_model_name;
    std::string gemini_base_url;

    std::string openai_api_key;
    std::string openai_model_name;
    std::string openai_base_url;

    std::string openrouter_api_key;
    std::string openrouter_model_name;

    std::string anthropic_api_key;
    std::string anthropic_model_name;
    std::string anthropic_base_url;

    std::string copilot_proxy_address;
    std::string copilot_model_name;

    int xref_context_count;
    int xref_analysis_depth;
    int xref_code_snippet_lines;
    double bulk_processing_delay;
    int max_prompt_tokens;

    int max_root_func_scan_count;
    int max_root_func_candidates;
    double temperature;

    std::vector<std::string> gemini_models;
    std::vector<std::string> openai_models;
    std::vector<std::string> openrouter_models;
    std::vector<std::string> anthropic_models;
    std::vector<std::string> copilot_models;

    settings_t();
    void save();
    void load(aida_plugin_t* plugin_instance);
    std::string get_active_api_key() const;

private:
    bool load_from_file();
    void prompt_for_api_key();
};

extern settings_t g_settings;