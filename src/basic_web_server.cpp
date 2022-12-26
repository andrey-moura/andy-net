#include "string.hpp"

const std::string& operator||(const std::string& left, const std::string& right)
{
    if(left.empty()) return right;
    return left;
}

std::string uva::string::tolower(const std::string& __str)
{
    std::string str;
    str.reserve(__str.size());

    for(const char& c : __str) {
        if(isalpha(c)) {
            str.push_back(std::tolower(c));
        } else {
            str.push_back(c);
        }
    }

    return str;
}

std::string uva::string::prefix_sufix(const std::string& str, const std::string& prefix, const std::string& sufix)
{
    std::stringstream ss;

    if(prefix.size()) {
        ss << prefix;
    }

    ss << str;

    if(sufix.size()) {
        ss << sufix;
    }

    return ss.str();
}

std::string uva::string::split_on_upper(const std::string& s, char separator)
{
    std::vector<size_t> splits;

    for (size_t i = 1; i < s.size()-1; i++)
    {
        if (isupper(s[i]) && !isupper(s[i + 1]) || isupper(s[i]) && !isupper(s[i - 1]))
        {
            splits.push_back(i);
        }
    }

    std::string output;

    size_t lastSplit = 0;
    for (const size_t& split : splits)
    {
        output.append(s.substr(lastSplit, split - lastSplit) + separator);
        lastSplit = split;
    }

    output.append(s.substr(lastSplit));

    for (char& c : output)
    {
        if (isalpha(c)) {
            c = std::tolower((int)c);
        }
    }

    return output;
}

std::string uva::string::to_snake_case(const std::string& s)
{
    std::string splited_upper = uva::string::split_on_upper(s, '_');
    for(char& c : splited_upper)
    {
        if(isspace(c))
        {
            c = '_';
        }
    }
    std::string splited_numbers;
    splited_numbers.reserve(splited_upper.size());

    for(const char& c : splited_upper)
    {
        if(isdigit(c))
        {
            splited_numbers.push_back('_');
            splited_numbers.push_back(c);
            splited_numbers.push_back('_');
        } else {
            splited_numbers.push_back(c);
        }
        
    }

    return splited_numbers;
}

std::string uva::string::replace(const std::string& _str, const char& find, const char& replace)
{
    std::string str;
    str.reserve(_str.size());

    for(const char &c : _str)
    {
        if(c == find)
        {
            str.push_back(replace);
        } else 
        {
            str.push_back(c);
        }
    }

    return str;
}

std::vector<std::string_view> uva::string::tokenize(std::string_view str)
{
    std::vector<std::string_view> tokens;

    const char* begin = str.data();
    const char* end = str.data()+str.size();
    const char* iterator = begin;

    const char* current_token_begin = nullptr;
    const char* current_token_end = nullptr;

    while(iterator != end)
    {
        if(isspace(*iterator)) {
            if(current_token_begin)
            {
                current_token_end = iterator;
            }
        } else {
            if(!current_token_begin)
            {
                current_token_begin = iterator;
            }
        }

        if(current_token_begin && current_token_end)
        {
            tokens.push_back(std::string_view(current_token_begin, current_token_end-current_token_begin));
            current_token_begin = nullptr;
            current_token_end = nullptr;
        }

        ++iterator;
    }

    if(current_token_begin && str.size())
    {
        tokens.push_back(std::string_view(current_token_begin, end-current_token_begin));
    }

    return tokens;
}

std::string uva::string::capitalize(const std::string& __string)
{
    std::string capitalized;
    capitalized.reserve(__string.size());

    bool last_was_space = true;

    for(char c : __string)
    {
        if(last_was_space) {
            c = toupper(c);
        }

        last_was_space = isspace(c);

        capitalized.push_back(c);
    }

    return capitalized;
}

bool uva::string::ends_with(const std::string& __string, const std::vector<std::string>& __suffixes)
{
    for(const std::string& suffix : __suffixes)
    {
        if(__string.ends_with(suffix)) return true;
    }

    return false;
}

bool uva::string::isvowel(const char& __c)
{
    char lowercased = std::tolower(__c);

    switch(lowercased)
    {
        case 'a':
            return true;
        break;
        case 'e':
            return true;
        break;
        case 'i':
            return true;
        break;
        case 'o':
            return true;
        break;
        case 'u':
            return true;
        default:
            return false;
        break;
    }
}

bool uva::string::isconsonant(const char& __c)
{
    return isalpha(__c) && !isvowel(__c);
}

std::string uva::string::pluralize(std::string __string)
{
//following https://www.grammar.cl/Notes/Plural_Nouns.htm

    std::string lowercased = uva::string::tolower(__string);

    //add exceptions here
    std::map<std::string, std::string> exceptions = {
        { "quiz",     "quizzes" },
        { "roof",     "roofs" },
        { "cliff",    "cliffs" },
        { "chief",    "chiefs" },
        { "belief",   "beliefs" },
        { "chef",     "chefs" },
        { "piano",    "pianos" },
        { "halo",     "halos" },
        { "photo",    "photos" },
        { "man",	  "men" },
        { "woman",	  "women" },
        { "child",	  "children" },
        { "foot",	  "feet" },
        { "tooth",	  "teeth" },
        { "goose",	  "geese" },
        { "mouse",	  "mice" },
        { "fish",	  "fish" },
        { "sheep",	  "sheep" },
        { "deer",	  "deer" },
        { "moose",	  "moose" },
        { "aircraft", "aircraft" },
    };

    auto it = exceptions.find(lowercased);

    if(it != exceptions.end()) {
        return it->second;
    }

    //1. When the noun ends in S, SH, CH, X or Z*, we add -ES to the noun.
    if(ends_with(lowercased, { "s", "sh", "ch", "x", "z" } ))
    {
        return __string + "es";
    }
    
    // When the noun ends in a VOWEL + Y, we add -S to the noun.
    // if(ends_with(lowercased, { "ay", "ey", "iy", "oy", "uy" } ))
    // {
    //     return __string + "s";
    // }

    //3. When the noun ends in a CONSONANT + Y, we remove Y and add -IES to the noun.
    if(lowercased.ends_with('y') && lowercased.size() > 2 && isconsonant(lowercased[lowercased.size()-2]))
    {
        __string.pop_back();
        return __string + "ies";
    }

    //4. If the noun ends in F or FE, we remove the F/FE and add -VES to the noun.
    if(lowercased.ends_with("fe"))
    {
        __string.pop_back();
        __string.pop_back();

        return __string + "ves";
    } else if(__string.ends_with('f'))
    {
        __string.pop_back();
        return __string + "ves";
    }

    //5. If the noun ends in a CONSONANT + O, we normally add -ES to the noun.
    if(lowercased.ends_with('o') && lowercased.size() > 2 && isconsonant(lowercased[lowercased.size()-2]))
    {
        return __string + "es";
    }

    //In general the plural of a noun is formed by adding -S to the noun.
    return __string + 's';
}