/*
 * Boost Software License - Version 1.0
 *
 * Mustache
 * Copyright 2015-2020 Kevin Wojniak
 *
 * Permission is hereby granted, free of charge, to any person or organization
 * obtaining a copy of the software and accompanying documentation covered by
 * this license (the "Software") to use, reproduce, display, distribute,
 * execute, and transmit the Software, and to prepare derivative works of the
 * Software, and to permit third-parties to whom the Software is furnished to
 * do so, all subject to the following:
 *
 * The copyright notices in the Software and this entire statement, including
 * the above license grant, this restriction and the following disclaimer,
 * must be included in all copies of the Software, in whole or in part, and
 * all derivative works of the Software, unless such copies or derivative
 * works are solely in the form of machine-executable object code generated by
 * a source language processor.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
 * SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
 * FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef KAINJOW_MUSTACHE_HPP
#define KAINJOW_MUSTACHE_HPP

#include <cassert>
#include <cctype>
#include <functional>
#include <iostream>
#include <memory>
#include <sstream>
#include <unordered_map>
#include <vector>

#define KAINJOW_MUSTACHE_VERSION_MAJOR 5
#define KAINJOW_MUSTACHE_VERSION_MINOR 0
#define KAINJOW_MUSTACHE_VERSION_PATCH 0

namespace kainjow {

template<typename string_type, typename basic_data>
struct mustache_ns {
    static string_type trim(const string_type &s) {
        auto it = s.begin();
        while (it != s.end() && std::isspace(*it)) {
            it++;
        }
        auto rit = s.rbegin();
        while (rit.base() != it && std::isspace(*rit)) {
            rit++;
        }
        return { it, rit.base() };
    }

    static string_type html_escape(const string_type &s) {
        string_type ret;
        ret.reserve(s.size() * 2);
        for (const auto ch : s) {
            switch (ch) {
            case '&':
                ret.append({ '&', 'a', 'm', 'p', ';' });
                break;
            case '<':
                ret.append({ '&', 'l', 't', ';' });
                break;
            case '>':
                ret.append({ '&', 'g', 't', ';' });
                break;
            case '\"':
                ret.append({ '&', 'q', 'u', 'o', 't', ';' });
                break;
            case '\'':
                ret.append({ '&', 'a', 'p', 'o', 's', ';' });
                break;
            default:
                ret.append(1, ch);
                break;
            }
        }
        return ret;
    }

    static std::vector<string_type> split(const string_type &s, typename string_type::value_type delim) {
        std::vector<string_type>                                  elems;
        std::basic_stringstream<typename string_type::value_type> ss(s);
        string_type                                               item;
        while (std::getline(ss, item, delim)) {
            elems.push_back(item);
        }
        return elems;
    }

    class basic_renderer {
    public:
        using type1 = std::function<string_type(const string_type &)>;
        using type2 = std::function<string_type(const string_type &, bool escaped)>;

        string_type operator()(const string_type &text) const {
            return type1_(text);
        }

        string_type operator()(const string_type &text, bool escaped) const {
            return type2_(text, escaped);
        }

        basic_renderer(const type1 &t1, const type2 &t2)
            : type1_(t1)
            , type2_(t2) {}

        const type1 &type1_;
        const type2 &type2_;

        template<typename StringType>
        friend class basic_mustache;
    };

    /*
    class basic_lambda_t {
    public:
        using type1 = std::function<string_type(const string_type &)>;
        using type2 = std::function<string_type(const string_type &, const basic_renderer &render)>;

        basic_lambda_t(const type1 &t)
            : type1_(new type1(t)) {}
        basic_lambda_t(const type2 &t)
            : type2_(new type2(t)) {}

        bool         is_type1() const { return static_cast<bool>(type1_); }
        bool         is_type2() const { return static_cast<bool>(type2_); }

        const type1 &type1_value() const { return *type1_; }
        const type2 &type2_value() const { return *type2_; }

        // Copying
        basic_lambda_t(const basic_lambda_t &l) {
            if (l.type1_) {
                type1_.reset(new type1(*l.type1_));
            } else if (l.type2_) {
                type2_.reset(new type2(*l.type2_));
            }
        }

        string_type operator()(const string_type &text) const {
            return (*type1_)(text);
        }

        string_type operator()(const string_type &text, const basic_renderer &render) const {
            return (*type2_)(text, render);
        }

    private:
        std::unique_ptr<type1> type1_;
        std::unique_ptr<type2> type2_;
    };
    */

    using basic_list    = std::vector<basic_data>;
    using basic_object  = std::unordered_map<string_type, basic_data>;
    using basic_partial = std::function<string_type()>;
    /*
    using basic_lambda  = typename basic_lambda_t::type1;
    using basic_lambda2 = typename basic_lambda_t::type2;
    */

    class delimiter_set {
    public:
        string_type begin;
        string_type end;
        delimiter_set()
            : begin(default_begin)
            , end(default_end) {}
        bool                     is_default() const { return begin == default_begin && end == default_end; }
        static const string_type default_begin;
        static const string_type default_end;
    };

    // static const string_type delimiter_set::default_begin(2, '{');
    // static const string_type delimiter_set::default_end(2, '}');

    class basic_context {
    public:
        virtual ~basic_context()                                             = default;
        virtual void              push(const basic_data *data)               = 0;
        virtual void              pop()                                      = 0;

        virtual const basic_data *get(const string_type &name) const         = 0;
        virtual const basic_data *get_partial(const string_type &name) const = 0;
    };

    class context : public basic_context {
    public:
        context(const basic_data *data) {
            push(data);
        }

        context() {
        }

        virtual void push(const basic_data *data) override {
            items_.insert(items_.begin(), data);
        }

        virtual void pop() override {
            items_.erase(items_.begin());
        }

        virtual const basic_data *get(const string_type &name) const override {
            // process {{.}} name
            if (name.size() == 1 && name.at(0) == '.') {
                return items_.front();
            }
            if (name.find('.') == string_type::npos) {
                // process normal name without having to split which is slower
                for (const auto &item : items_) {
                    const auto var = item->get(name);
                    if (var) {
                        return var;
                    }
                }
                return nullptr;
            }
            // process x.y-like name
            const auto names = split(name, '.');
            for (const auto &item : items_) {
                auto var = item;
                for (const auto &n : names) {
                    var = var->get(n);
                    if (!var) {
                        break;
                    }
                }
                if (var) {
                    return var;
                }
            }
            return nullptr;
        }

        virtual const basic_data *get_partial(const string_type &name) const override {
            for (const auto &item : items_) {
                const auto var = item->get(name);
                if (var) {
                    return var;
                }
            }
            return nullptr;
        }

        context(const context &) = delete;
        context &operator=(const context &) = delete;

    private:
        std::vector<const basic_data *> items_;
    };

    class line_buffer_state {
    public:
        string_type data;
        bool        contained_section_tag = false;

        bool        is_empty_or_contains_only_whitespace() const {
            for (const auto ch : data) {
                // don't look at newlines
                if (ch != ' ' && ch != '\t') {
                    return false;
                }
            }
            return true;
        }

        void clear() {
            data.clear();
            contained_section_tag = false;
        }
    };

    class context_internal {
    public:
        basic_context    &ctx;
        delimiter_set     delim_set;
        line_buffer_state line_buffer;

        context_internal(basic_context &a_ctx)
            : ctx(a_ctx) {
        }
    };

    enum class tag_type {
        text,
        variable,
        unescaped_variable,
        section_begin,
        section_end,
        section_begin_inverted,
        comment,
        partial,
        set_delimiter,
    };

    class mstch_tag /* gcc doesn't allow "tag tag;" so rename the class :( */ {
    public:
        string_type                    name;
        tag_type                       type = tag_type::text;
        std::shared_ptr<string_type>   section_text;
        std::shared_ptr<delimiter_set> delim_set;
        bool                           is_section_begin() const {
            return type == tag_type::section_begin || type == tag_type::section_begin_inverted;
        }
        bool is_section_end() const {
            return type == tag_type::section_end;
        }
    };

    class context_pusher {
    public:
        context_pusher(context_internal &ctx, const basic_data *data)
            : ctx_(ctx) {
            ctx.ctx.push(data);
        }
        ~context_pusher() {
            ctx_.ctx.pop();
        }
        context_pusher(const context_pusher &) = delete;
        context_pusher &operator=(const context_pusher &) = delete;

    private:
        context_internal &ctx_;
    };

    class component {
    private:
        using string_size_type = typename string_type::size_type;

    public:
        string_type            text;
        mstch_tag              tag;
        std::vector<component> children;
        string_size_type       position = string_type::npos;

        enum class walk_control {
            walk, // "continue" is reserved :/
            stop,
            skip,
        };
        using walk_callback = std::function<walk_control(component &)>;

        component() {}
        component(const string_type &t, string_size_type p)
            : text(t), position(p) {}

        bool is_text() const {
            return tag.type == tag_type::text;
        }

        bool is_newline() const {
            return is_text() && ((text.size() == 2 && text[0] == '\r' && text[1] == '\n') || (text.size() == 1 && (text[0] == '\n' || text[0] == '\r')));
        }

        bool is_non_newline_whitespace() const {
            return is_text() && !is_newline() && text.size() == 1 && (text[0] == ' ' || text[0] == '\t');
        }

        void walk_children(const walk_callback &callback) {
            for (auto &child : children) {
                if (child.walk(callback) != walk_control::walk) {
                    break;
                }
            }
        }

    private:
        walk_control walk(const walk_callback &callback) {
            walk_control control{ callback(*this) };
            if (control == walk_control::stop) {
                return control;
            } else if (control == walk_control::skip) {
                return walk_control::walk;
            }
            for (auto &child : children) {
                control = child.walk(callback);
                if (control == walk_control::stop) {
                    return control;
                }
            }
            return control;
        }
    };

    class parser {
    public:
        parser(const string_type &input, context_internal &ctx, component &root_component, string_type &error_message) {
            parse(input, ctx, root_component, error_message);
        }

    private:
        void parse(const string_type &input, context_internal &ctx, component &root_component, string_type &error_message) const {
            using string_size_type = typename string_type::size_type;
            using streamstring     = std::basic_ostringstream<typename string_type::value_type>;

            const string_type             brace_delimiter_end_unescaped(3, '}');
            const string_size_type        input_size{ input.size() };

            bool                          current_delimiter_is_brace{ ctx.delim_set.is_default() };

            std::vector<component *>      sections{ &root_component };
            std::vector<string_size_type> section_starts;
            string_type                   current_text;
            string_size_type              current_text_position = string_type::npos;

            current_text.reserve(input_size);

            const auto process_current_text = [&current_text, &current_text_position, &sections]() {
                if (!current_text.empty()) {
                    const component comp{ current_text, current_text_position };
                    sections.back()->children.push_back(comp);
                    current_text.clear();
                    current_text_position = string_type::npos;
                }
            };

            const std::vector<string_type> whitespace{
                string_type(1, '\r') + string_type(1, '\n'),
                string_type(1, '\n'),
                string_type(1, '\r'),
                string_type(1, ' '),
                string_type(1, '\t'),
            };

            for (string_size_type input_position = 0; input_position != input_size;) {
                bool parse_tag = false;

                if (input.compare(input_position, ctx.delim_set.begin.size(), ctx.delim_set.begin) == 0) {
                    process_current_text();

                    // Tag start delimiter
                    parse_tag = true;
                } else {
                    bool parsed_whitespace = false;
                    for (const auto &whitespace_text : whitespace) {
                        if (input.compare(input_position, whitespace_text.size(), whitespace_text) == 0) {
                            process_current_text();

                            const component comp{ whitespace_text, input_position };
                            sections.back()->children.push_back(comp);
                            input_position += whitespace_text.size();

                            parsed_whitespace = true;
                            break;
                        }
                    }

                    if (!parsed_whitespace) {
                        if (current_text.empty()) {
                            current_text_position = input_position;
                        }
                        current_text.append(1, input[input_position]);
                        input_position++;
                    }
                }

                if (!parse_tag) {
                    continue;
                }

                // Find the next tag start delimiter
                const string_size_type tag_location_start = input_position;

                // Find the next tag end delimiter
                string_size_type   tag_contents_location{ tag_location_start + ctx.delim_set.begin.size() };
                const bool         tag_is_unescaped_var{ current_delimiter_is_brace && tag_location_start != (input_size - 2) && input.at(tag_contents_location) == ctx.delim_set.begin.at(0) };
                const string_type &current_tag_delimiter_end{ tag_is_unescaped_var ? brace_delimiter_end_unescaped : ctx.delim_set.end };
                const auto         current_tag_delimiter_end_size = current_tag_delimiter_end.size();
                if (tag_is_unescaped_var) {
                    ++tag_contents_location;
                }
                const string_size_type tag_location_end{ input.find(current_tag_delimiter_end, tag_contents_location) };
                if (tag_location_end == string_type::npos) {
                    streamstring ss;
                    ss << "Unclosed tag at " << tag_location_start;
                    error_message.assign(ss.str());
                    return;
                }

                // Parse tag
                const string_type tag_contents{ trim(string_type{ input, tag_contents_location, tag_location_end - tag_contents_location }) };
                component         comp;
                if (!tag_contents.empty() && tag_contents[0] == '=') {
                    if (!parse_set_delimiter_tag(tag_contents, ctx.delim_set)) {
                        streamstring ss;
                        ss << "Invalid set delimiter tag at " << tag_location_start;
                        error_message.assign(ss.str());
                        return;
                    }
                    current_delimiter_is_brace = ctx.delim_set.is_default();
                    comp.tag.type              = tag_type::set_delimiter;
                    comp.tag.delim_set.reset(new delimiter_set(ctx.delim_set));
                }
                if (comp.tag.type != tag_type::set_delimiter) {
                    parse_tag_contents(tag_is_unescaped_var, tag_contents, comp.tag);
                }
                comp.position = tag_location_start;
                sections.back()->children.push_back(comp);

                // Start next search after this tag
                input_position = tag_location_end + current_tag_delimiter_end_size;

                // Push or pop sections
                if (comp.tag.is_section_begin()) {
                    sections.push_back(&sections.back()->children.back());
                    section_starts.push_back(input_position);
                } else if (comp.tag.is_section_end()) {
                    if (sections.size() == 1) {
                        streamstring ss;
                        ss << "Unopened section \"" << comp.tag.name << "\" at " << comp.position;
                        error_message.assign(ss.str());
                        return;
                    }
                    sections.back()->tag.section_text.reset(new string_type(input.substr(section_starts.back(), tag_location_start - section_starts.back())));
                    sections.pop_back();
                    section_starts.pop_back();
                }
            }

            process_current_text();

            // Check for sections without an ending tag
            root_component.walk_children([&error_message](component &comp) -> typename component::walk_control {
                if (!comp.tag.is_section_begin()) {
                    return component::walk_control::walk;
                }
                if (comp.children.empty() || !comp.children.back().tag.is_section_end() || comp.children.back().tag.name != comp.tag.name) {
                    streamstring ss;
                    ss << "Unclosed section \"" << comp.tag.name << "\" at " << comp.position;
                    error_message.assign(ss.str());
                    return component::walk_control::stop;
                }
                comp.children.pop_back(); // remove now useless end section component
                return component::walk_control::walk;
            });
            if (!error_message.empty()) {
                return;
            }
        }

        bool is_set_delimiter_valid(const string_type &delimiter) const {
            // "Custom delimiters may not contain whitespace or the equals sign."
            for (const auto ch : delimiter) {
                if (ch == '=' || std::isspace(ch)) {
                    return false;
                }
            }
            return true;
        }

        bool parse_set_delimiter_tag(const string_type &contents, delimiter_set &delimiter_set) const {
            // Smallest legal tag is "=X X="
            if (contents.size() < 5) {
                return false;
            }
            if (contents.back() != '=') {
                return false;
            }
            const auto contents_substr = trim(contents.substr(1, contents.size() - 2));
            const auto spacepos        = contents_substr.find(' ');
            if (spacepos == string_type::npos) {
                return false;
            }
            const auto nonspace = contents_substr.find_first_not_of(' ', spacepos + 1);
            assert(nonspace != string_type::npos);
            const string_type begin = contents_substr.substr(0, spacepos);
            const string_type end   = contents_substr.substr(nonspace, contents_substr.size() - nonspace);
            if (!is_set_delimiter_valid(begin) || !is_set_delimiter_valid(end)) {
                return false;
            }
            delimiter_set.begin = begin;
            delimiter_set.end   = end;
            return true;
        }

        void parse_tag_contents(bool is_unescaped_var, const string_type &contents, mstch_tag &tag) const {
            if (is_unescaped_var) {
                tag.type = tag_type::unescaped_variable;
                tag.name = contents;
            } else if (contents.empty()) {
                tag.type = tag_type::variable;
                tag.name.clear();
            } else {
                switch (contents.at(0)) {
                case '#':
                    tag.type = tag_type::section_begin;
                    break;
                case '^':
                    tag.type = tag_type::section_begin_inverted;
                    break;
                case '/':
                    tag.type = tag_type::section_end;
                    break;
                case '>':
                    tag.type = tag_type::partial;
                    break;
                case '&':
                    tag.type = tag_type::unescaped_variable;
                    break;
                case '!':
                    tag.type = tag_type::comment;
                    break;
                default:
                    tag.type = tag_type::variable;
                    break;
                }
                if (tag.type == tag_type::variable) {
                    tag.name = contents;
                } else {
                    string_type name{ contents };
                    name.erase(name.begin());
                    tag.name = trim(name);
                }
            }
        }
    };

    template<typename StringType>
    class basic_mustache {
    public:
        using string_t = StringType;

        basic_mustache(const string_t &input)
            : basic_mustache() {
            context          ctx;
            context_internal context{ ctx };
            parser           parser{ input, context, root_component_, error_message_ };
        }

        bool is_valid() const {
            return error_message_.empty();
        }

        const string_t &error_message() const {
            return error_message_;
        }

        using escape_handler = std::function<string_t(const string_t &)>;
        void set_custom_escape(const escape_handler &escape_fn) {
            escape_ = escape_fn;
        }

        template<typename stream_type>
        stream_type &render(const basic_data &data, stream_type &stream) {
            render(data, [&stream](const string_t &str) {
                stream << str;
            });
            return stream;
        }

        string_t render(const basic_data &data) {
            std::basic_ostringstream<typename string_t::value_type> ss;
            return render(data, ss).str();
        }

        template<typename stream_type>
        stream_type &render(basic_context &ctx, stream_type &stream) {
            context_internal context{ ctx };
            render([&stream](const string_t &str) {
                stream << str;
            },
                    context);
            return stream;
        }

        string_t render(basic_context &ctx) {
            std::basic_ostringstream<typename string_t::value_type> ss;
            return render(ctx, ss).str();
        }

        using render_handler = std::function<void(const string_t &)>;
        void render(const basic_data &data, const render_handler &handler) {
            if (!is_valid()) {
                return;
            }
            context          ctx{ &data };
            context_internal context{ ctx };
            render(handler, context);
        }

        basic_mustache()
            : escape_(html_escape) {
        }

    private:
        using string_size_type = typename string_t::size_type;

        basic_mustache(const string_t &input, context_internal &ctx)
            : basic_mustache() {
            parser parser{ input, ctx, root_component_, error_message_ };
        }

        string_t render(context_internal &ctx) {
            std::basic_ostringstream<typename string_t::value_type> ss;
            render([&ss](const string_t &str) {
                ss << str;
            },
                    ctx);
            return ss.str();
        }

        void render(const render_handler &handler, context_internal &ctx, bool root_renderer = true) {
            root_component_.walk_children([&handler, &ctx, this](component &comp) -> typename component::walk_control {
                return render_component(handler, ctx, comp);
            });
            // process the last line, but only for the top-level renderer
            if (root_renderer) {
                render_current_line(handler, ctx, nullptr);
            }
        }

        void render_current_line(const render_handler &handler, context_internal &ctx, const component *comp) const {
            // We're at the end of a line, so check the line buffer state to see
            // if the line had tags in it, and also if the line is now empty or
            // contains whitespace only. if this situation is true, skip the line.
            bool output = true;
            if (ctx.line_buffer.contained_section_tag && ctx.line_buffer.is_empty_or_contains_only_whitespace()) {
                output = false;
            }
            if (output) {
                handler(ctx.line_buffer.data);
                if (comp) {
                    handler(comp->text);
                }
            }
            ctx.line_buffer.clear();
        }

        void render_result(context_internal &ctx, const string_t &text) const {
            ctx.line_buffer.data.append(text);
        }

        typename component::walk_control render_component(const render_handler &handler, context_internal &ctx, component &comp) {
            if (comp.is_text()) {
                if (comp.is_newline()) {
                    render_current_line(handler, ctx, &comp);
                } else {
                    render_result(ctx, comp.text);
                }
                return component::walk_control::walk;
            }

            const mstch_tag  &tag{ comp.tag };
            const basic_data *var = nullptr;
            switch (tag.type) {
            case tag_type::variable:
            case tag_type::unescaped_variable:
                if ((var = ctx.ctx.get(tag.name)) != nullptr) {
                    if (!render_variable(handler, var, ctx, tag.type == tag_type::variable)) {
                        return component::walk_control::stop;
                    }
                }
                break;
            case tag_type::section_begin:
                if ((var = ctx.ctx.get(tag.name)) != nullptr) {
                    // if (var->is_lambda() || var->is_lambda2()) {
                    //     if (!render_lambda(handler, var, ctx, render_lambda_escape::optional, *comp.tag.section_text, true)) {
                    //         return component::walk_control::stop;
                    //     }
                    // } else
                    if (!var->is_false() && !var->is_empty_list()) {
                        render_section(handler, ctx, comp, var);
                    }
                }
                return component::walk_control::skip;
            case tag_type::section_begin_inverted:
                if ((var = ctx.ctx.get(tag.name)) == nullptr || var->is_false() || var->is_empty_list()) {
                    render_section(handler, ctx, comp, var);
                }
                return component::walk_control::skip;
            case tag_type::partial:
                if ((var = ctx.ctx.get_partial(tag.name)) != nullptr && (var->is_partial() || var->is_string())) {
                    const auto    &partial_result = var->is_partial() ? var->partial_value()() : var->string_value();
                    basic_mustache tmpl{ partial_result };
                    tmpl.set_custom_escape(escape_);
                    if (!tmpl.is_valid()) {
                        error_message_ = tmpl.error_message();
                    } else {
                        tmpl.render(handler, ctx, false);
                        if (!tmpl.is_valid()) {
                            error_message_ = tmpl.error_message();
                        }
                    }
                    if (!tmpl.is_valid()) {
                        return component::walk_control::stop;
                    }
                }
                break;
            case tag_type::set_delimiter:
                ctx.delim_set = *comp.tag.delim_set;
                break;
            default:
                break;
            }

            return component::walk_control::walk;
        }

        // enum class render_lambda_escape {
        //     escape,
        //     unescape,
        //     optional,
        // };
        //
        // bool render_lambda(const render_handler &handler, const basic_data *var, context_internal &ctx, render_lambda_escape escape, const string_t &_text, bool parse_with_same_context) {
        //     const typename basic_renderer::type2 render2 = [this, &ctx, parse_with_same_context, escape](const string_t &text, bool escaped) {
        //         const auto process_template = [this, &ctx, escape, escaped](basic_mustache &tmpl) -> string_t {
        //             if (!tmpl.is_valid()) {
        //                 error_message_ = tmpl.error_message();
        //                 return {};
        //             }
        //             context_internal render_ctx{ ctx.ctx }; // start a new line_buffer
        //             const auto       str = tmpl.render(render_ctx);
        //             if (!tmpl.is_valid()) {
        //                 error_message_ = tmpl.error_message();
        //                 return {};
        //             }
        //             bool do_escape = false;
        //             switch (escape) {
        //             case render_lambda_escape::escape:
        //                 do_escape = true;
        //                 break;
        //             case render_lambda_escape::unescape:
        //                 do_escape = false;
        //                 break;
        //             case render_lambda_escape::optional:
        //                 do_escape = escaped;
        //                 break;
        //             }
        //             return do_escape ? escape_(str) : str;
        //         };
        //         if (parse_with_same_context) {
        //             basic_mustache tmpl{ text, ctx };
        //             tmpl.set_custom_escape(escape_);
        //             return process_template(tmpl);
        //         }
        //         basic_mustache tmpl{ text };
        //         tmpl.set_custom_escape(escape_);
        //         return process_template(tmpl);
        //     };
        //     const typename basic_renderer::type1 render = [&render2](const string_t &text) {
        //         return render2(text, false);
        //     };
        //     if (var->is_lambda2()) {
        //         const basic_renderer renderer{ render, render2 };
        //         render_result(ctx, var->lambda2_value()(_text, renderer));
        //     } else {
        //         render_current_line(handler, ctx, nullptr);
        //         render_result(ctx, render(var->lambda_value()(_text)));
        //     }
        //     return error_message_.empty();
        // }

        bool render_variable(const render_handler & /*handler*/, const basic_data *var, context_internal &ctx, bool escaped) {
            if (var->is_string()) {
                const auto &varstr = var->string_value();
                render_result(ctx, escaped ? escape_(varstr) : varstr);
                // } else if (var->is_lambda()) {
                //     const render_lambda_escape escape_opt = escaped ? render_lambda_escape::escape : render_lambda_escape::unescape;
                //     return render_lambda(handler, var, ctx, escape_opt, {}, false);
                // } else if (var->is_lambda2()) {
                //     using streamstring = std::basic_ostringstream<typename string_t::value_type>;
                //     streamstring ss;
                //     ss << "Lambda with render argument is not allowed for regular variables";
                //     error_message_ = ss.str();
                //     return false;
            }
            return true;
        }

        void render_section(const render_handler &handler, context_internal &ctx, component &incomp, const basic_data *var) {
            const auto callback = [&handler, &ctx, this](component &comp) -> typename component::walk_control {
                return render_component(handler, ctx, comp);
            };
            if (var && var->is_non_empty_list()) {
                while (const auto *item = var->next_list_item()) {
                    // account for the section begin tag
                    ctx.line_buffer.contained_section_tag = true;

                    const context_pusher ctxpusher{ ctx, item };
                    incomp.walk_children(callback);

                    // ctx may have been cleared. account for the section end tag
                    ctx.line_buffer.contained_section_tag = true;
                }
            } else if (var) {
                // account for the section begin tag
                ctx.line_buffer.contained_section_tag = true;

                const context_pusher ctxpusher{ ctx, var };
                incomp.walk_children(callback);

                // ctx may have been cleared. account for the section end tag
                ctx.line_buffer.contained_section_tag = true;
            } else {
                // account for the section begin tag
                ctx.line_buffer.contained_section_tag = true;

                incomp.walk_children(callback);

                // ctx may have been cleared. account for the section end tag
                ctx.line_buffer.contained_section_tag = true;
            }
        }

    private:
        string_t       error_message_;
        component      root_component_;
        escape_handler escape_;
    };

    using mustache = basic_mustache<std::string>;
    using data     = basic_data;
    using list     = basic_list;
    using partial  = basic_partial;
    using renderer = basic_renderer;
    // using lambda   = basic_lambda;
    // using lambda2  = basic_lambda2;
    // using lambda_t = basic_lambda_t;

}; // namespace-like mustache_ns
template<typename string_type, typename basic_data>
const string_type mustache_ns<string_type, basic_data>::delimiter_set::default_begin = string_type(2, '{');
template<typename string_type, typename basic_data>
const string_type mustache_ns<string_type, basic_data>::delimiter_set::default_end = string_type(2, '}');

} // namespace kainjow

#endif // KAINJOW_MUSTACHE_HPP
