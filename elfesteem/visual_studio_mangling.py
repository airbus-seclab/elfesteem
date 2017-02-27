#! /usr/bin/env python

def symbol_demangle(symbol, verbose=False):
    # Some documentation on Visual C++ name mangling is at
    #   https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/undname.c
    #   https://github.com/nico/demumble (includes wine's undname)
    #   https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling
    #   http://sourceforge.net/projects/php-ms-demangle/
    # A web interface to a demangler is available at https://demangler.com/
    # I also have made some tests with undname.exe of Visual Studio 14.0.
    data = DemangleData(symbol, verbose=verbose)
    # 'data' will contain the rest, not parsed
    try:
        return symbol_demangle_reentrant(data), data
    except AssertionError:
        return symbol, ''
    except TypeError:
        return symbol, ''
    except KeyError:
        return symbol, ''

# We define quote and backquote to be reconfigurable
quote_b = "`"
quote_e = "'"

class DemangleData(object):
    def __init__(self, value, verbose=False):
        # The main data is the input string.
        self.value = value
        # But we also store, for backreferences, the list of name fragments
        # and the list of arguments (non-primitive types only).
        self.fragments = []
        self.arguments = []
        # In templates, the backreference lists are pushed on a history stack.
        self.history = []
        self.verbose = verbose
    def advance(self, count):
        # This is linear in the size of self.value, therefore the complexity
        # of symbol_demangle_reentrant is quadratic, which makes it vulnerable
        # to DoS attacks. That's why DemangleData's interface can support an
        # implementation such that self.value is constant and the current
        # position in self.value is stored in e.g. self.pos; I chose to
        # modify self.value, it seems more understandable.
        self.value = self.value[count:]
    def __getitem__(self, pos):
        return self.value.__getitem__(pos)
    def index(self, pos):
        return self.value.index(pos)
    def __repr__(self):
        return repr(self.value)
    def __len__(self):
        return len(self.value)
    def add_fragment(self, fragment):
        self.fragments.append(fragment)
    def add_argument(self, argument):
        self.arguments.append(argument)
    def enter_template(self):
        self.history.append( (self.fragments, self.arguments) )
        self.fragments, self.arguments = [], []
    def exit_template(self):
        self.fragments, self.arguments = self.history.pop()
    def is_in_template(self):
        # '?' data type depends on whether we are in a template
        return len(self.history) > 0
    def log(self, msg, *args):
        if self.verbose: print('    %-25s REST=%r ARG=%r FRAG=%r'
            %(msg%args,self,self.arguments,self.fragments))

def symbol_demangle_reentrant(data):
    # Reentrant: can be called for nested symbols.
    if data[:6] == '__mep@':
        # undname.exe does not expand symbols beginning with __mep@,
        # but they are generated when using C++/CLI and correspond
        # to prefixed mangled symbols.
        data.advance(6)
        return '[MEP] ' + symbol_demangle_reentrant(data)
    elif data[:1] != '?':
        data.log('Not Mangled')
        name = str(data.value)
        data.advance(len(data))
        return name
    data.advance(1)
    if data[:1] == '$':
        # Neither a variable nor a function: just a name with a template
        # Example: '?$a@PAUb@@' which means 'a<struct b *>'
        data.advance(1)
        name = extract_template(data)
        assert len(data) == 0
        return name
    elif data[:1] == '@':
        # Found by reversing vcruntime140.dll
        # Don't know when such names are generated
        data.advance(1)
        data.log('CV: prefix')
        return 'CV: ' + symbol_demangle_reentrant(data)
    elif data[:3] == '?_C':
        # Neither a variable nor a function: just `string'
        # The rest is ignored
        name = quote_b + 'string' + quote_e
        data.advance(len(data))
        return name
    # Variable or function: starts with a list of name fragments,
    # continues with type information.
    if data[:1] == '?':
        data.advance(1)
        name = name_extract_special(data)
    else:
        name = []
    name += name_extract_list(data)
    if '0' <= data[:1] <= '9' or data[:2] == '$B':
        return symbol_demangle_variable(name, data)
    if 'A' <= data[:1] <= 'Z' or data[:1] == '$':
        return symbol_demangle_function(name, data)

def symbol_demangle_variable(name, data):
    # Access level and storage class
    thunk, access = parse_value(data, thunk_access, logmsg='TYPE=%s ACCESS=%s')
    add_name = ''
    if thunk == 'VAR':
        # NB: ret is of type DataType, because it may be a function pointer
        ret = data_type(data)
        data.log('TYPE=%s', ret)
        cv = ' '.join(cv_class_modifiers(data))
        if cv: cv += ' '
        ret += ' ' + cv
    elif thunk == 'OPT':
        ret = ' '.join(cv_class_modifiers(data))
        if ret: ret += ' '
        if data[:1] != '@':
            add_name = name_extract_list(data)
            add_name = '::'.join(reversed(add_name))
            add_name = "{for %s%s%s}" % (quote_b, add_name, quote_e)
        data.log('OPT_NAME=%r', add_name)
        assert data[:1] == '@'
        data.advance(1)
    elif thunk == 'vcall':
        n1 = decode_number(data)
        data.log('VCALL{%d}', n1)
        add_name = '{%d,{flat}}'%n1 + quote_e + ' }' + quote_e
        assert data[:1] == 'A'
        data.advance(1)
        ret = parse_value(data, calling_convention, logmsg='CALL=%r')
    name = '::'.join(reversed(name))
    ret += name
    if access: access += ' '
    return access + str(ret) + add_name

def symbol_demangle_function(name, data):
    if data[:3] in ('$$F', '$$H'):
        # C++/CLI
        # https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling
        # identifies $$F as a 'function modifier' for C++/CLI meaning
        # the the function is managed. This web page mentions $$F in the
        # data_types section, but it does not appear with data types,
        # it appears before the thunk_access letters.
        # The symbol with $$F is the 'managed entry point', the other
        # being the 'native entry point'.
        #
        # Visual Studio also generates $$H for 'main', with unknown
        # meaning...
        #
        # Apparently this could be ignored, because undname.exe outputs
        # the same decoding when $$F or $$H is present. We add a prefix,
        # it seems more informative.
        prefix = {
            '$$F': '[managed] ',
            '$$H': '[MANAGED] ',
            }[data[:3]]
        data.advance(3)
        return prefix + symbol_demangle_function(name, data)
    thunk, access = parse_value(data, thunk_access, logmsg='TYPE=%s ACCESS=%s')
    if thunk == 'vtordisp':
        vtor = [str(decode_number(data)) for _ in range(2)]
    elif thunk == 'vtordispex':
        assert data[:1] == '4'
        data.advance(1)
        vtor = [str(decode_number(data)) for _ in range(4)]
    cv = ''
    if access and not 'static' in access:
        cli_retval = {
            '$A': '',
            '$C': '%',
            }
        cli = parse_value(data, cli_retval)
        if cli:
            data.log('C++/CLI Return Value')
            cv = cli
        cv = ' '.join(cv_class_modifiers(data)) + cv
    ret, func_call, args = symbol_demangle_function_prototype(data)
    name, ret = name_finalize(name, ret)
    name = '::'.join(reversed(name))
    if thunk is not None and thunk.startswith('vtordisp'):
        name += quote_b + thunk + '{' + ','.join(vtor) + '}' + quote_e + ' '
    if ret and access: access += ' '
    ret += ' ' + func_call + name + args + cv
    return access + str(ret)

def symbol_demangle_function_prototype(data):
    # Used when demangling a function, but also for function pointers
    # and member function pointers.
    func_call = parse_value(data, calling_convention, logmsg='CALL=%r')
    ret = data_type(data)
    data.log('RET=%s', ret)
    args = arg_list(data, stop='XZ@')
    assert data[:1] == 'Z'; data.advance(1) # Function argument list ends with Z
    args = '(' + ','.join(args) + ')'
    return ret, func_call, args

def name_extract_special(data):
    # The symbol's name optionally starts with a special fragment
    name = []
    fragment = parse_value(data, special_fragment)
    if fragment is not None:
        data.log('SPEC=%r', fragment)
        name.append(fragment)
    elif data[:2] == '_P':
        data.advance(2)
        fragment = quote_b + 'udt returning' + quote_e
        fragment += name_extract_special(data)[0]
        name.append(fragment)
    elif data[:3] == '_R0':
        data.advance(3)
        fragment = data_type(data)
        fragment += ' ' + quote_b + 'RTTI Type Descriptor' + quote_e
        name.append(str(fragment))
    elif data[:3] == '_R1':
        data.advance(3)
        fragment = quote_b + 'RTTI Base Class Descriptor at (%d,%d,%d,%d)' + quote_e
        fragment = fragment % tuple(decode_number(data) for _ in range(4))
        name.append(fragment)
    elif data[:2] == '$?':
        # operator template
        data.advance(2)
        fragment = parse_value(data, special_fragment)
        fragment += '<%s>' % data_type(data)
        name.append(fragment)
        assert data[:1] == '@'
        data.advance(1)
    elif data[:1] == '$':
        # normal template
        data.advance(1)
        fragment = extract_template(data)
        name.append(fragment)
    return name

def name_extract_list(data):
    # Other fragments cannot be in 'special_fragment' nor operator template.
    # If they begin with '?$' they are normal templates, with '??' they are
    # nested names, and other fragments beginning with '?' are quoted numeric.
    name = []
    while data[:1] != '@':
        fragment = extract_name_fragment(data)
        name.append(fragment)
    assert data[:1] == '@'
    data.advance(1)
    data.log('NAME=%r', name)
    return name

def extract_name_string(data):
    assert len(data)
    assert data[0] != '?'
    idx = data.index('@')
    fragment = data[:idx]
    data.advance(idx+1)
    data.add_fragment(fragment)
    data.log('NAME=%r', fragment)
    return fragment

def extract_name_fragment(data):
    if len(data) and data[0] in '0123456789':
        # fragment backreference
        data.log('BACKREF_FRG=%s', data[0])
        fragment = data.fragments[int(data[0])]
        data.advance(1)
    elif data[:2] == '??':
        # nested name
        data.advance(1)
        fragment = quote_b + symbol_demangle_reentrant(data) + quote_e
    elif data[:2] == '?$':
        # template
        data.advance(2)
        fragment = extract_template(data)
        data.add_fragment(fragment)
    elif data[:2] == '?A':
        # anonymous namespace
        idx = data.index('@')
        data.advance(idx+1)
        fragment = quote_b + 'anonymous namespace' + quote_e
    elif data[:1] == '?':
        # numbered namespace
        data.advance(1)
        i = decode_number(data)
        fragment = quote_b + str(i) + quote_e
    else:
        # name (text)
        fragment = extract_name_string(data)
    data.log('FRAGMENT=%r', fragment)
    return fragment

def extract_template(data):
    data.log('TEMPLATE start')
    data.enter_template()
    name = extract_name_string(data)
    args = arg_list(data, stop='Z@')
    data.exit_template()
    fragment = '%s<%s>'%(name, ','.join(args))
    data.log('TEMPLATE=%r', fragment)
    return fragment

def cv_class_modifiers(data):
    mod = []
    while len(data) and data[0] in 'EFI':
        mod.append({
            'E': '__ptr64',
            'F': '__unaligned',
            'I': '__restrict',
        }[data[0]])
        data.advance(1)
    cv = {
            'A': '',
            'B': 'const',
            'C': 'volatile',
            'D': 'const volatile',
        }[data[:1]]
    data.advance(1)
    data.log('CVC_MOD=%r %r', cv, mod)
    return [cv] + mod

def decode_number(data):
    if data[:1] == '?': sign = -1; data.advance(1)
    else:               sign = 1
    if data[:1] == '@':
        data.advance(1)
        return 0
    elif data[:1] in '0123456789':
        val = 1+int(data[0])
        data.advance(1)
        return sign*val
    elif len(data) and data[0] in 'ABCDEFGHIJKLMNOP':
        i = 0
        while len(data) and data[0] != '@':
            i *= 16
            i += ord(data[0])-ord('A')
            data.advance(1)
        data.advance(1)
        return sign*i

class DataType(object):
    # Usually a data type is a string, but if it is a function type,
    # then it is a triplet of strings
    #     ( return type, calling convention & qualifiers, arguments )
    # We create a dedicated class, because we want to use += (aka. __iadd__)
    def __init__(self, value):
        if isinstance(value, tuple):
            self.value = (str(value[0]), value[1], value[2])
        else:
            self.value = value
    def __repr__(self):
        return '<%s %r>'%(self.__class__.__name__, self.value)
    def __str__(self):
        if isinstance(self.value, tuple):
            r, c, a = self.value
            if c: c = '(' + c + ')'
            return r + ' ' + c + a
        else:
            return self.value
    def __iadd__(self, other):
        if isinstance(self.value, tuple):
            r, c, a = self.value
            self.value = (r, c + other, a)
        else:
            self.value += other
        return self
    def append(self, other):
        if isinstance(self.value, tuple):
            r, c, a = self.value
            self.value = (r, c, a + other)
        else:
            self.value += other
        return self
    def prepend(self, other):
        if isinstance(self.value, tuple):
            r, c, a = self.value
            self.value = (other + r, c, a)
        else:
            self.value = other + self.value
        return self
    def __nonzero__(self):
        # For python2
        return self.__bool__()
    def __bool__(self):
        # For python3
        return bool(len(self.value))

def data_type(data, depth = 0):
    data.log('TYPE depth %d', depth)
    if   len(data) and data[0] in '0123456789':
        # argument backreference
        pos = int(data[0])
        data.log('BACKREF_ARG=%d', pos)
        data.advance(1)
        result = data.arguments[pos]
    elif data[:2] == 'P6':
        # Function pointer
        # The result of 'data_type' is not a string, because if it is
        # an argument of a function it needs to be converted to
        # '%s(%s)%s'%result but if it is a return type it needs
        # to be converted to '%s(%s f(args))%s'
        data.advance(2)
        result = DataType(symbol_demangle_function_prototype(data))
        result += '*'
    elif data[:2] == 'P8':
        # Member function pointer
        data.advance(2)
        assert len(data)
        fragment = data.fragments[int(data[0])]
        data.advance(1)
        assert data[:1] == '@'
        data.advance(1)
        cv = ' '.join(cv_class_modifiers(data))
        result = DataType(symbol_demangle_function_prototype(data))
        result += fragment+'::*'
        result.append(cv)
    elif data[:3] == '__Z':
        # HACK. do nothing
        data.advance(3)
        result = data_type(data)
    elif data[:2] in ('A$', 'P$'):
        cli0 = data[0]
        data.advance(2)
        assert len(data)
        # Managed C++ properties
        #   https://en.wikipedia.org/wiki/Managed_Extensions_for_C%2B%2B
        #   Now deprecated, was designed for .Net and CLR.
        #   There were __gc, __value, __interface, __abstract, __sealed
        #   and _pin modifiers.
        # C++/CLI
        #   Replaces Managed C++, included in Visual Studio 2005
        #   The both Managed C++ and C++/CLI are well described at
        #   https://msdn.microsoft.com/en-us/library/ms379603(VS.80).aspx
        data.log('C++/CLI Arguments')
        cli1 = data[0]
        if cli1 in 'ABC':
            data.advance(1)
            cli_arguments = {
                'PA': (' ^', ''),
                'AA': (' %', ''),
                # Not sure whether these next two are generated by the compiler
                'PC': (' %', ''),
                'AC': (' %', ''),
                # pin_ptr decoding seems invalid, the < is not closed,
                # but that's what undname.exe outputs.
                'PB': (' *', 'cli::pin_ptr<'),
                'AB': (' &', 'cli::pin_ptr<'),
                }
            postfix, prefix = cli_arguments[cli0+cli1]
            c = cv_class_modifiers(data)
            result = data_type(data, depth=depth+1)
            if c[0] != '': result += ' ' + c[0]
            result += postfix
            result.prepend(prefix)
            if len(c) > 1: result += ' ' + ' '.join(c[1:])
        elif cli1 in '01':
            dim = int(data[:2], 16)
            data.advance(2)
            data.advance(1) # ignored, apparently
            result = data_type(data, depth=depth+1)
            result.prepend('cli::array<')
            if dim == 1: result += ' >^'
            else:        result += ' ,%d>^' % dim
        else:
            # VS 14.0's undname.exe does some additional decoding,
            # e.g. ?a@@$$FYMHP$DFCH@Z
            # becomes 'int __clrcall a(cli::array<int ,342>^)'
            # but this is clearly a bug of undname.exe
            assert False
    elif data[:1] == '?' and data.is_in_template():
        # Template parameters
        data.advance(1)
        i = decode_number(data)
        result = DataType(quote_b + 'template-parameter-%d'%i + quote_e)
    elif data[:1] == '$' and data[:2] != '$$' and data.is_in_template():
        # Various types of template parameters
        template_type = data[1]
        data.advance(2)
        if template_type == '0':
            # Template instanciated with a numeric value. Example:
            #   template<int N> struct S1 { int a[N]; };
            #   S1<10> s1;
            i = decode_number(data)
            result = DataType(str(i))
        elif template_type == '1':
            # Template instanciated with a static object. Example:
            #   template<const int&> struct S2 {};
            #   int N = 1;
            #   S2<N> s2;
            result = DataType('&%s'% symbol_demangle_reentrant(data))
        elif template_type in '2FG':
            # Decoding obtained by trial and error with undname.exe,
            # but the result seems meaningless.
            h = str(ord(data[0])-ord('/'))
            data.advance(1)
            i = decode_number(data)
            if   template_type == '2':
                result = DataType('%s.%se%d'%(h[0],h[1:],i))
            elif template_type == 'F':
                result = DataType('{%s,%d}'%(h,i))
            elif template_type == 'G':
                j = decode_number(data)
                result = DataType('{%s,%d,%d}'%(h,i,j))
        elif template_type == 'D':
            # This is compatible with wine's undname, but is not known to
            # the undname.exe of Visual Studio 14.0.
            i = decode_number(data)
            result = DataType(quote_b + 'template-parameter%d'%i + quote_e)
        else:
            raise KeyError('TemplateParameter<%s>'%template_type)
    elif data[:3] == '$$B':
        # $$B seems useless because it calls data_type with no changes,
        # but it is needed by undname.exe in some cases.
        data.advance(3)
        result = data_type(data)
    elif data[:1] == 'Y' and (depth > 0 or data.is_in_template()):
        # Pointer to multidimensional array
        data.advance(1)
        dim = decode_number(data)
        val = [ '[%d]'%decode_number(data) for _ in range(dim) ]
        result = str(data_type(data))
        result = DataType((result, '', ''.join(val)))
    elif data[:2] == '_$':
        # __w64 type
        data.advance(2)
        result = data_type(data, depth=depth+1).prepend('__w64 ')
    elif data[:2] == '_O':
        # Array
        dimension = 1
        data.advance(2)
        cv = ' '.join(cv_class_modifiers(data))
        if cv: cv = ' ' + cv
        while data[:2] == '_O':
            dimension += 1
            data.advance(2)
            cv_class_modifiers(data)
        result = data_type(data, depth=depth+1)
        result.append(cv + ' ' + '[]' * dimension)
    else:
        category, result = parse_value(data, data_types)
        if category == 'COMPLEX':
            data.log('COMPLEX_TYPE')
            if result == 'enum':
                assert 'int' == parse_value(data, enum_types)
            result = DataType(result)
            name = name_extract_list(data)
            name = '::'.join(reversed(name))
            result += ' ' + name
        elif category == 'MODIFIER':
            # The type modifier is output in two parts, because the qualifier
            # is not present when there are nested pointer/references,
            # detected by looking at the variable 'depth'.
            # The mixing of 'm' and 'c' outputs the same order as undname.exe
            m = result
            c = cv_class_modifiers(data)
            data.log('CVM(%d) %s %s', depth, c, m)
            if depth > 0: m = [m[0]]
            cm = []
            if c[0] != '': cm.append(c[0])
            if m[0] != '': cm.append(m[0])
            cm = ' '.join(cm + c[1:] + m[1:])
            if cm != '': cm = ' ' + cm
            result = data_type(data, depth=depth+1)
            result += cm
        else:
            assert category == 'SIMPLE'
            result = DataType(result)
    data.log('TYPE=%r', result)
    return result

def arg_list(data, stop=None):
    # For function arguments, 'X' is terminating     => stop = 'XZ@'
    # For template arguments, 'X' is not terminating => stop = 'Z@'
    data.log('ARGS start')
    args = []
    while len(data):
        if data[0] in stop: break
        primitive_type = data[0] in 'CDEFGHIJKMNO'
        a = data_type(data)
        if a is None: break
        args.append(str(a))
        if not primitive_type: data.add_argument(a)
    data.log('ARGS=%r', args)
    if not len(data):
        # Neither a variable nor a function: just a type with template
        return args
    if data[:1] == 'X':
        # void as the only argument
        args.append('void')
    elif data[:2] == 'ZZ':
        # ellipsis only when at the end of the argument list
        args.append('...')
    else:
        assert data[:1] == '@'
    data.advance(1)
    return args

def name_finalize(name, ret):
    # Some special fragments need to be replaced after everything has
    # been computed.
    if   name[0] == '?0':
        # constructor
        assert len(name) >= 2
        name[0] = name[1]
        ret = ''
    elif name[0] == '?1':
        # destructor
        assert len(name) >= 2
        name[0] = '~' + name[1]
        ret = ''
    elif name[0] == '?B':
        # operator returntype
        name[0] = 'operator ' + str(ret)
        ret = ''
    elif name[0] in ('?__E', '?__F', '?__K'):
        assert len(name) >= 2
        name[1] = {
            '?__E': quote_b + "dynamic initializer for '%s'" + quote_e,
            '?__F': quote_b + "dynamic atexit destructor for '%s'" + quote_e,
            '?__K': 'operator "" %s',
            }[name[0]] % name[1]
        name[:1] = []
    return name, ret

def parse_value(data, table, logmsg=None):
    # Function for accessing the tables below
    for k in table:
        if data[:len(k)] == k:
            data.advance(len(k))
            if logmsg is not None:
                data.log(logmsg % table[k])
            return table[k]
    if logmsg is not None: data.log(logmsg % 'NONE')

special_fragment = {
    '0': '?0', # to be done by name_finalize()
    '1': '?1', # to be done by name_finalize()
    '2': 'operator new',
    '3': 'operator delete',
    '4': 'operator=',
    '5': 'operator>>',
    '6': 'operator<<',
    '7': 'operator!',
    '8': 'operator==',
    '9': 'operator!=',
    'A': 'operator[]',
    'B': '?B', # to be done by name_finalize()
    'C': 'operator->',
    'D': 'operator*',
    'E': 'operator++',
    'F': 'operator--',
    'G': 'operator-',
    'H': 'operator+',
    'I': 'operator&',
    'J': 'operator->*',
    'K': 'operator/',
    'L': 'operator%',
    'M': 'operator<',
    'N': 'operator<=',
    'O': 'operator>',
    'P': 'operator>=',
    'Q': 'operator,',
    'R': 'operator()',
    'S': 'operator~',
    'T': 'operator^',
    'U': 'operator|',
    'V': 'operator&&',
    'W': 'operator||',
    'X': 'operator*=',
    'Y': 'operator+=',
    'Z': 'operator-=',
    '_0': 'operator/=',
    '_1': 'operator%=',
    '_2': 'operator>>=',
    '_3': 'operator<<=',
    '_4': 'operator&=',
    '_5': 'operator|=',
    '_6': 'operator^=',
    '_7': quote_b + 'vftable' + quote_e,
    '_8': quote_b + 'vbtable' + quote_e,
    '_9': quote_b + 'vcall' + quote_e,
    '_A': quote_b + 'typeof' + quote_e,
    '_B': quote_b + 'local static guard' + quote_e,
    #_C     just returns 'string' and forgets the rest of the input
    '_D': quote_b + 'vbase destructor' + quote_e,
    '_E': quote_b + 'vector deleting destructor' + quote_e,
    '_F': quote_b + 'default constructor closure' + quote_e,
    '_G': quote_b + 'scalar deleting destructor' + quote_e,
    '_H': quote_b + 'vector constructor iterator' + quote_e,
    '_I': quote_b + 'vector destructor iterator' + quote_e,
    '_J': quote_b + 'vector vbase constructor iterator' + quote_e,
    '_K': quote_b + 'virtual displacement map' + quote_e,
    '_L': quote_b + 'eh vector constructor iterator' + quote_e,
    '_M': quote_b + 'eh vector destructor iterator' + quote_e,
    '_N': quote_b + 'eh vector vbase constructor iterator' + quote_e,
    '_O': quote_b + 'copy constructor closure' + quote_e,
    #_P     'udt returning' followed by a special fragment
    #_R0    'RTTI Type Descriptor' followed by a data type
    #_R1    'RTTI Base Class Descriptor' followed by four numbers
    '_R2': quote_b + 'RTTI Base Class Array' + quote_e,
    '_R3': quote_b + 'RTTI Class Hierarchy Descriptor' + quote_e,
    '_R4': quote_b + 'RTTI Complete Object Locator' + quote_e,
    '_S': quote_b + 'local vftable' + quote_e,
    '_T': quote_b + 'local vftable constructor closure' + quote_e,
    '_U': 'operator new[]',
    '_V': 'operator delete[]',
    '_X': quote_b + 'placement delete closure' + quote_e,
    '_Y': quote_b + 'placement delete[] closure' + quote_e,
    '__A': quote_b + 'managed vector constructor iterator' + quote_e,
    '__B': quote_b + 'managed vector destructor iterator' + quote_e,
    '__C': quote_b + 'eh vector copy constructor iterator' + quote_e,
    '__D': quote_b + 'eh vector vbase copy constructor iterator' + quote_e,
    '__E': '?__E', # to be done by name_finalize()
    '__F': '?__F', # to be done by name_finalize()
    '__G': quote_b + 'vector copy constructor iterator' + quote_e,
    '__H': quote_b + 'vector vbase copy constructor iterator' + quote_e,
    '__I': quote_b + 'managed vector copy constructor iterator' + quote_e,
    '__J': quote_b + 'local static thread guard' + quote_e,
    '__K': '?__K', # to be done by name_finalize()
    }

data_types = {
     # We should set '@' to 'void' if we want the same output as wine's undname
    '@':   ('SIMPLE',   '',),
    '?':   ('MODIFIER', ['',   ]),
    'A':   ('MODIFIER', ['&',  ]),
    'B':   ('MODIFIER', ['& volatile', ]),
    'C':   ('SIMPLE',   'signed char',),
    'D':   ('SIMPLE',   'char',),
    'E':   ('SIMPLE',   'unsigned char',),
    'F':   ('SIMPLE',   'short',),
    'G':   ('SIMPLE',   'unsigned short',),
    'H':   ('SIMPLE',   'int',),
    'I':   ('SIMPLE',   'unsigned int',),
    'J':   ('SIMPLE',   'long',),
    'K':   ('SIMPLE',   'unsigned long',),
    'M':   ('SIMPLE',   'float',),
    'N':   ('SIMPLE',   'double',),
    'O':   ('SIMPLE',   'long double',),
    'P':   ('MODIFIER', ['*',  ]),
    'Q':   ('MODIFIER', ['*',  'const']),
    'R':   ('MODIFIER', ['*',  'volatile']),
    'S':   ('MODIFIER', ['*',  'const volatile']),
    'T':   ('COMPLEX',  'union'),
    'U':   ('COMPLEX',  'struct'),
    'V':   ('COMPLEX',  'class'),
    'W':   ('COMPLEX',  'enum'),
    'X':   ('SIMPLE',   'void',),
    'Y':   ('COMPLEX',  'cointerface'),
    '_D':  ('SIMPLE',   '__int8',),
    '_E':  ('SIMPLE',   'unsigned __int8',),
    '_F':  ('SIMPLE',   '__int16',),
    '_G':  ('SIMPLE',   'unsigned __int16',),
    '_H':  ('SIMPLE',   '__int32',),
    '_I':  ('SIMPLE',   'unsigned __int32',),
    '_J':  ('SIMPLE',   '__int64',),
    '_K':  ('SIMPLE',   'unsigned __int64',),
    '_L':  ('SIMPLE',   '__int128',),
    '_M':  ('SIMPLE',   'unsigned __int128',),
    '_N':  ('SIMPLE',   'bool',),
    #_O   =SPECIAL CASE= Array
    '_S':  ('SIMPLE',   'char16_t',),
    '_U':  ('SIMPLE',   'char32_t',),
    '_W':  ('SIMPLE',   'wchar_t',),
    '_X':  ('COMPLEX',  'coclass'),
    '_Y':  ('COMPLEX',  'cointerface'),
    #_$'  =SPECIAL CASE= __w64 type
    #$$A  =TODO= (found by reversing vcruntime140.dll, more reverse is needed)
    #$$B  =SPECIAL CASE= Apparently no effect
    '$$C': ('MODIFIER', ['',   ]),
    '$$Q': ('MODIFIER', ['&&', ]),
    '$$R': ('MODIFIER', ['&&', 'volatile']),
    #$$S  =TODO= (found by reversing vcruntime140.dll, more reverse is needed)
    '$$T': ('SIMPLE',   'std::nullptr_t'),
    #$$Y  =TODO= (found by reversing vcruntime140.dll, more reverse is needed)
    }

enum_types = {
    # Here are the enum types mentioned at
    # https://en.wikiversity.org/wiki/Visual_C%2B%2B_name_mangling
    # Note that only type 4 aka 'int' is used by "modern versions"
    # of Visual Studio.
    '0': 'char',
    '1': 'unsigned char',
    '2': 'short',
    '3': 'unsigned short',
    '4': 'int',
    '5': 'unsigned int',
    '6': 'long',
    '7': 'unsigned long',
    }

thunk_access = {
    'A': (None, 'private:'),
    'B': (None, 'private:'),
    'C': (None, 'private: static'),
    'D': (None, 'private: static'),
    'E': (None, 'private: virtual'),
    'F': (None, 'private: virtual'),
    'G': (None, 'private: thunk'),
    'H': (None, 'private: thunk'),
    'I': (None, 'protected:'),
    'J': (None, 'protected:'),
    'K': (None, 'protected: static'),
    'K': (None, 'protected: static'),
    'M': (None, 'protected: virtual'),
    'N': (None, 'protected: virtual'),
    'O': (None, 'protected: thunk'),
    'P': (None, 'protected: thunk'),
    'Q': (None, 'public:'),
    'R': (None, 'public:'),
    'S': (None, 'public: static'),
    'T': (None, 'public: static'),
    'U': (None, 'public: virtual'),
    'V': (None, 'public: virtual'),
    'W': (None, 'public: thunk'),
    'X': (None, 'public: thunk'),
    'Y': (None, ''),
    'Z': (None, ''),
    '0': ('VAR', 'private: static'),
    '1': ('VAR', 'protected: static'),
    '2': ('VAR', 'public: static'),
    '3': ('VAR', ''), # private non-static
    '4': ('VAR', ''), # protected non-static
    '5': ('VAR', ''), # public non-static
    '6': ('OPT', ''),
    '7': ('OPT', ''),
    '$0': ('vtordisp',   '[thunk]:private: virtual'),
    '$1': ('vtordisp',   '[thunk]:private: virtual'),
    '$2': ('vtordisp',   '[thunk]:protected: virtual'),
    '$3': ('vtordisp',   '[thunk]:protected: virtual'),
    '$4': ('vtordisp',   '[thunk]:public: virtual'),
    '$5': ('vtordisp',   '[thunk]:public: virtual'),
    '$B': ('vcall',      '[thunk]:'),
    '$R': ('vtordispex', '[thunk]:public: virtual'),
    }

calling_convention = {
    'A': '__cdecl ',
    'B': '__cdecl __dll_export ',
    'C': '__pascal ',
    'D': '__pascal __dll_export ',
    'E': '__thiscall ',
    'F': '__thiscall __dll_export ',
    'G': '__stdcall ',
    'H': '__stdcall __dll_export ',
    'I': '__fastcall ',
    'J': '__fastcall __dll_export ',
    'K': '',
    'L': '__dll_export ',
    'M': '__clrcall ',
    'N': '__clrcall __dll_export ',
    'O': '__eabi ',
    'P': '__eabi __dll_export ',
    'Q': '__vectorcall ',
    }

if __name__ == "__main__":
    import sys
    verbose = False
    for s in sys.argv[1:]:
        if s == '-v': verbose = True; continue
        n, r = symbol_demangle(s, verbose=verbose)
        if r: n += ' Rest(%s)'%r
        print(n)
