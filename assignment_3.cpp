
#include <cctype>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

enum TokenType {
    INTEGER,
    REAL,
    IDENTIFIER,
    KEYWORD,
    OPERATOR,
    SEPERATOR,
    COMMENT,
    UNKNOWN
};

struct Token {
    TokenType type;
    string lexeme;
};

unordered_map<std::string, TokenType> keywords = {
    {"while", KEYWORD},   {"endwhile", KEYWORD}, {"if", KEYWORD},
    {"endif", KEYWORD},   {"else", KEYWORD},     {"return", KEYWORD},
    {"true", KEYWORD},    {"false", KEYWORD},    {"integer", KEYWORD},
    {"boolean", KEYWORD}, {"real", KEYWORD},     {"scan", KEYWORD},
    {"print", KEYWORD},   {"function", KEYWORD}};

unordered_map<char, TokenType> operators = {
    {'+', OPERATOR}, {'-', OPERATOR}, {'*', OPERATOR}, {'/', OPERATOR},
    {'=', OPERATOR}, {'<', OPERATOR}, {'>', OPERATOR}, {'!', OPERATOR},
};

unordered_map<char, TokenType> seperators = {
    {';', SEPERATOR}, {',', SEPERATOR}, {'(', SEPERATOR}, {')', SEPERATOR},
    {'{', SEPERATOR}, {'}', SEPERATOR}, {'$', SEPERATOR},
};

enum State {
    S_START,
    S_IDENTIFIER,
    S_INTEGER,
    S_REAL,
    S_OPERATOR,
    S_SEPERATOR,
    S_COMMENT,
    S_ERROR,
    S_KEYWORD
};

Token lexer(const string& input, size_t& pos) {
    State state        = S_START;
    std::string lexeme = "";
    while (pos <= input.length()) {
        char ch = input[pos];
        switch (state) {
            case S_START:
                if (isspace(ch)) {
                    pos++;
                    continue;
                } else if (isalpha(ch)) {
                    state = S_IDENTIFIER;
                    lexeme += ch;
                    pos++;
                    break;
                } else if (isdigit(ch)) {
                    state = S_INTEGER;
                    lexeme += ch;
                    pos++;
                    break;
                } else if (operators.count(ch)) {
                    state = S_OPERATOR;
                    lexeme += ch;
                    pos++;
                    break;
                } else if (seperators.count(ch)) {
                    state = S_SEPERATOR;
                    lexeme += ch;
                    pos++;
                    break;
                } else if (ch == '[' && pos + 1 < input.length() &&
                           input[pos + 1] == '*') {
                    state = S_COMMENT;
                    lexeme += "[*";
                    pos += 2;
                    break;
                } else {
                    state = S_ERROR;
                    lexeme += ch;
                    pos++;
                    break;
                }
            case S_IDENTIFIER:
                while (pos < input.length() &&
                       (isalnum(input[pos]) || input[pos] == '_')) {
                    lexeme += input[pos++];
                }
                if (keywords.count(lexeme))
                    return {KEYWORD, lexeme};
                return {IDENTIFIER, lexeme};
            case S_INTEGER:
                while (pos < input.length() && isdigit(input[pos]))
                    lexeme += input[pos++];
                if (pos < input.length() && input[pos] == '.') {
                    state = S_REAL;
                    lexeme += input[pos++];
                    break;
                }
                return {INTEGER, lexeme};
            case S_REAL:
                if (pos >= input.length() || !isdigit(input[pos]))
                    return {UNKNOWN, lexeme};
                while (pos < input.length() && isdigit(input[pos]))
                    lexeme += input[pos++];
                return {REAL, lexeme};
            case S_OPERATOR:
                if (pos < input.length() &&
                    ((lexeme[0] == '=' && input[pos] == '=') ||
                     (lexeme[0] == '!' && input[pos] == '=') ||
                     (lexeme[0] == '<' && input[pos] == '=') ||
                     (lexeme[0] == '>' && input[pos] == '='))) {
                    lexeme += input[pos++];
                }
                return {OPERATOR, lexeme};
            case S_SEPERATOR:
                if (lexeme == "$" && pos < input.length() && input[pos] == '$')
                    lexeme += input[pos++];
                return {SEPERATOR, lexeme};
            case S_COMMENT:
                while (pos < input.length() - 1 &&
                       !(input[pos] == '*' && input[pos + 1] == ']')) {
                    lexeme += input[pos++];
                }
                if (pos < input.length() - 1) {
                    lexeme += "*]";
                    pos += 2;
                }
                return {COMMENT, lexeme};
            case S_ERROR:
                while (pos < input.length() && !isspace(input[pos]) &&
                       !operators.count(input[pos]) &&
                       !seperators.count(input[pos])) {
                    lexeme += input[pos++];
                }
                return {UNKNOWN, lexeme};
        }
    }
    return {UNKNOWN, lexeme};
}

struct SymbolEntry {
    int memory_location;
    std::string type;
};

struct Instruction {
    std::string op;
    std::string operand;
};

int memory_address_counter = 10000;
std::map<std::string, SymbolEntry> symbol_table;
std::vector<Instruction> instruction_table;

void insert_symbol(const std::string& id, const std::string& type = "integer") {
    if (symbol_table.find(id) != symbol_table.end()) {
        std::cerr << "Semantic Error: Variable '" << id
                  << "' already declared.\n";
    } else {
        symbol_table[id] = {memory_address_counter++, type};
    }
}

int get_address(const std::string& id) {
    if (symbol_table.find(id) == symbol_table.end()) {
        std::cerr << "Semantic Error: Variable '" << id
                  << "' used without declaration.\n";
        return -1;
    }
    return symbol_table[id].memory_location;
}

void generate_instruction(const std::string& op,
                          const std::string& operand = "") {
    instruction_table.push_back({op, operand});
}

void print_symbol_table() {
    std::cout << "\nSymbol Table:\nIdentifier\tMemoryLocation\tType\n";
    for (const auto& pair : symbol_table)
        std::cout << pair.first << "\t\t" << pair.second.memory_location
                  << "\t\t" << pair.second.type << "\n";
}

void print_instruction_table() {
    std::cout << "\nInstruction Table:\n";
    int i = 1;
    for (const auto& instr : instruction_table) {
        std::cout << i++ << "\t" << instr.op;
        if (!instr.operand.empty())
            std::cout << "\t" << instr.operand;
        std::cout << "\n";
    }
}

// Includes: Token matching, Declaration handling with symbol table integration,
// Expression parsing with assembly generation

class Parser {
   public:
    Parser(std::vector<Token>& tokens, const std::string* tokenNames)
        : tokens_listy(tokens), token_index(0), token_names(tokenNames) {
    }

    Token get_next_token() {
        if (token_index < tokens_listy.size())
            return tokens_listy[token_index++];
        return {UNKNOWN, ""};
    }

    Token peek_token() const {
        if (token_index < tokens_listy.size())
            return tokens_listy[token_index];
        return {UNKNOWN, ""};
    }

    void match(const std::string& expected_lexeme) {
        Token token = get_next_token();
        if (token.lexeme != expected_lexeme) {
            std::cerr << "Syntax Error: Expected '" << expected_lexeme
                      << "', found '" << token.lexeme << "'\n";
        }
    }

    void match(TokenType expected_token_type) {
        Token token = get_next_token();
        if (token.type != expected_token_type) {
            std::cerr << "Syntax Error: Expected token type '"
                      << token_names[expected_token_type] << "', found '"
                      << token_names[token.type] << "'\n";
        }
    }

    void Rat25S() {
        match("$$");
        Opt_DeclarationList();
        match("$$");
        StatementList();
        match("$$");
    }

    void Opt_DeclarationList() {
        Token token = peek_token();
        if (token.lexeme == "integer")
            DeclarationList();
    }

    void DeclarationList() {
        Declaration();
        match(";");
        while (peek_token().lexeme == "integer") {
            Declaration();
            match(";");
        }
    }
    // Parses a declaration: <Qualifier> <Identifier> (, <Identifier>)*

    void Declaration() {
        match("integer");
        std::string id = get_next_token().lexeme;
        insert_symbol(id);
        while (peek_token().lexeme == ",") {
            match(",");
            id = get_next_token().lexeme;
            insert_symbol(id);
        }
    }

    void StatementList() {
        while (is_statement_start(peek_token()))
            Statement();
    }

    // Determines and parses a single statement based on the starting token

    void Statement() {
        Token token = peek_token();
        if (token.lexeme == "{")
            Compound();
        else if (token.type == IDENTIFIER)
            Assign();
        else if (token.lexeme == "if")
            If();
        else if (token.lexeme == "print")
            Print();
        else if (token.lexeme == "scan")
            Scan();
        else if (token.lexeme == "while")
            While();
    }

    void Compound() {
        match("{");
        StatementList();
        match("}");
    }

    void Assign() {
        Token id = get_next_token();
        match("=");
        Expression();
        match(";");
        generate_instruction("POPM", std::to_string(get_address(id.lexeme)));
    }

    void If() {
        match("if");
        match("(");
        Condition();
        match(")");
        Statement();
        if (peek_token().lexeme == "else") {
            match("else");
            Statement();
        }
        match("endif");
    }

    void Print() {
        match("print");
        match("(");
        Expression();
        match(")");
        match(";");
        generate_instruction("SOUT");
    }

    void Scan() {
        match("scan");
        match("(");
        Token id = get_next_token();
        match(")");
        match(";");
        generate_instruction("SIN");
        generate_instruction("POPM", std::to_string(get_address(id.lexeme)));
    }

    void While() {
        match("while");
        match("(");
        Condition();
        match(")");
        Statement();
        match("endwhile");
    }

    void Condition() {
        Expression();
        Relop();
        Expression();
    }

    void Relop() {
        std::string op = peek_token().lexeme;
        match(op);
        if (op == "==")
            generate_instruction("EQU");
        else if (op == "!=")
            generate_instruction("NEQ");
        else if (op == "<")
            generate_instruction("LES");
        else if (op == ">")
            generate_instruction("GRT");
        else if (op == "<=")
            generate_instruction("LEQ");
        else if (op == ">=")
            generate_instruction("GEQ");
    }

    // Parses an expression with potential + or - operations

    void Expression() {
        Term();
        Expression_Prime();
    }

    void Expression_Prime() {
        Token token = peek_token();
        if (token.lexeme == "+") {
            match("+");
            Term();
            generate_instruction("A");
            Expression_Prime();
        } else if (token.lexeme == "-") {
            match("-");
            Term();
            generate_instruction("S");
            Expression_Prime();
        }
    }

    void Term() {
        Factor();
        Term_Prime();
    }

    void Term_Prime() {
        Token token = peek_token();
        if (token.lexeme == "*") {
            match("*");
            Factor();
            generate_instruction("M");
            Term_Prime();
        } else if (token.lexeme == "/") {
            match("/");
            Factor();
            generate_instruction("D");
            Term_Prime();
        }
    }

    void Factor() {
        Token token = peek_token();
        if (token.lexeme == "-") {
            match("-");
            Primary();
        } else {
            Primary();
        }
    }

    // Parses a primary value: identifier, integer, (expression), true/false

    void Primary() {
        Token token = peek_token();
        if (token.type == IDENTIFIER) {
            match(IDENTIFIER);
            generate_instruction("PUSHM",
                                 std::to_string(get_address(token.lexeme)));
        } else if (token.type == INTEGER) {
            match(INTEGER);
            generate_instruction("PUSHI", token.lexeme);
        } else if (token.lexeme == "(") {
            match("(");
            Expression();
            match(")");
        } else if (token.lexeme == "true") {
            match("true");
            generate_instruction("PUSHI", "1");
        } else if (token.lexeme == "false") {
            match("false");
            generate_instruction("PUSHI", "0");
        }
    }

    bool is_statement_start(const Token& token) const {
        return token.lexeme == "{" || token.type == IDENTIFIER ||
               token.lexeme == "if" || token.lexeme == "print" ||
               token.lexeme == "scan" || token.lexeme == "while";
    }

   private:
    std::vector<Token>& tokens_listy;
    size_t token_index;
    const std::string* token_names;
};
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "No test case file provided. Re-run with files please.\n";
        return 1;
    }

    const string token_names[] = {"INTEGER", "REAL",     "IDENTIFIER",
                                  "KEYWORD", "OPERATOR", "SEPERATOR",
                                  "COMMENT", "UNKNOWN"};

    for (int i = 1; i < argc; ++i) {
        ifstream input(argv[i]);
        if (!input.is_open()) {
            std::cout << "Error opening file:" << argv[i] << '\n';
            continue;
        }

        std::vector<Token> tokens_listy;
        string line;
        while (getline(input, line)) {
            size_t pos = 0;
            while (pos < line.length()) {
                Token token = lexer(line, pos);
                if (token.type != COMMENT)
                    tokens_listy.push_back(token);
            }
        }
        input.close();
        std::cout << "-----File: " << argv[i] << "-----\n";

        Parser parser(tokens_listy, token_names);
        parser.Rat25S();

        print_symbol_table();
        print_instruction_table();
    }
    return 0;
}
