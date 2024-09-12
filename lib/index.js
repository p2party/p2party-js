'use strict';

function getDefaultExportFromCjs (x) {
	return x && x.__esModule && Object.prototype.hasOwnProperty.call(x, 'default') ? x['default'] : x;
}

var assertString = {exports: {}};

(function (module, exports) {

	Object.defineProperty(exports, "__esModule", {
	  value: true
	});
	exports.default = assertString;
	function _typeof(o) { "@babel/helpers - typeof"; return _typeof = "function" == typeof Symbol && "symbol" == typeof Symbol.iterator ? function (o) { return typeof o; } : function (o) { return o && "function" == typeof Symbol && o.constructor === Symbol && o !== Symbol.prototype ? "symbol" : typeof o; }, _typeof(o); }
	function assertString(input) {
	  var isString = typeof input === 'string' || input instanceof String;
	  if (!isString) {
	    var invalidType = _typeof(input);
	    if (input === null) invalidType = 'null';else if (invalidType === 'object') invalidType = input.constructor.name;
	    throw new TypeError("Expected a string but received a ".concat(invalidType));
	  }
	}
	module.exports = exports.default;
	module.exports.default = exports.default; 
} (assertString, assertString.exports));

var assertStringExports = assertString.exports;

var isUUID$1 = {exports: {}};

(function (module, exports) {

	Object.defineProperty(exports, "__esModule", {
	  value: true
	});
	exports.default = isUUID;
	var _assertString = _interopRequireDefault(assertStringExports);
	function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }
	var uuid = {
	  1: /^[0-9A-F]{8}-[0-9A-F]{4}-1[0-9A-F]{3}-[0-9A-F]{4}-[0-9A-F]{12}$/i,
	  2: /^[0-9A-F]{8}-[0-9A-F]{4}-2[0-9A-F]{3}-[0-9A-F]{4}-[0-9A-F]{12}$/i,
	  3: /^[0-9A-F]{8}-[0-9A-F]{4}-3[0-9A-F]{3}-[0-9A-F]{4}-[0-9A-F]{12}$/i,
	  4: /^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i,
	  5: /^[0-9A-F]{8}-[0-9A-F]{4}-5[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i,
	  7: /^[0-9A-F]{8}-[0-9A-F]{4}-7[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/i,
	  all: /^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$/i
	};
	function isUUID(str, version) {
	  (0, _assertString.default)(str);
	  var pattern = uuid[![undefined, null].includes(version) ? version : 'all'];
	  return !!pattern && pattern.test(str);
	}
	module.exports = exports.default;
	module.exports.default = exports.default; 
} (isUUID$1, isUUID$1.exports));

var isUUIDExports = isUUID$1.exports;
var isUuidValidator = /*@__PURE__*/getDefaultExportFromCjs(isUUIDExports);

/**
 * Checks if the string is a UUID (version 3, 4 or 5).
 * If given value is not a string, then it returns false.
 */
function isUUID(value, version) {
    return typeof value === 'string' && isUuidValidator(value, version);
}

// src/utils/formatProdErrorMessage.ts
function formatProdErrorMessage$1(code) {
  return `Minified Redux error #${code}; visit https://redux.js.org/Errors?code=${code} for the full message or use the non-minified dev environment for full errors. `;
}

// src/utils/symbol-observable.ts
var $$observable = /* @__PURE__ */ (() => typeof Symbol === "function" && Symbol.observable || "@@observable")();
var symbol_observable_default = $$observable;

// src/utils/actionTypes.ts
var randomString = () => Math.random().toString(36).substring(7).split("").join(".");
var ActionTypes = {
  INIT: `@@redux/INIT${/* @__PURE__ */ randomString()}`,
  REPLACE: `@@redux/REPLACE${/* @__PURE__ */ randomString()}`,
  PROBE_UNKNOWN_ACTION: () => `@@redux/PROBE_UNKNOWN_ACTION${randomString()}`
};
var actionTypes_default = ActionTypes;

// src/utils/isPlainObject.ts
function isPlainObject$1(obj) {
  if (typeof obj !== "object" || obj === null)
    return false;
  let proto = obj;
  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }
  return Object.getPrototypeOf(obj) === proto || Object.getPrototypeOf(obj) === null;
}

// src/utils/kindOf.ts
function miniKindOf(val) {
  if (val === void 0)
    return "undefined";
  if (val === null)
    return "null";
  const type = typeof val;
  switch (type) {
    case "boolean":
    case "string":
    case "number":
    case "symbol":
    case "function": {
      return type;
    }
  }
  if (Array.isArray(val))
    return "array";
  if (isDate(val))
    return "date";
  if (isError(val))
    return "error";
  const constructorName = ctorName(val);
  switch (constructorName) {
    case "Symbol":
    case "Promise":
    case "WeakMap":
    case "WeakSet":
    case "Map":
    case "Set":
      return constructorName;
  }
  return Object.prototype.toString.call(val).slice(8, -1).toLowerCase().replace(/\s/g, "");
}
function ctorName(val) {
  return typeof val.constructor === "function" ? val.constructor.name : null;
}
function isError(val) {
  return val instanceof Error || typeof val.message === "string" && val.constructor && typeof val.constructor.stackTraceLimit === "number";
}
function isDate(val) {
  if (val instanceof Date)
    return true;
  return typeof val.toDateString === "function" && typeof val.getDate === "function" && typeof val.setDate === "function";
}
function kindOf(val) {
  let typeOfVal = typeof val;
  if (process.env.NODE_ENV !== "production") {
    typeOfVal = miniKindOf(val);
  }
  return typeOfVal;
}

// src/createStore.ts
function createStore(reducer, preloadedState, enhancer) {
  if (typeof reducer !== "function") {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(2) : `Expected the root reducer to be a function. Instead, received: '${kindOf(reducer)}'`);
  }
  if (typeof preloadedState === "function" && typeof enhancer === "function" || typeof enhancer === "function" && typeof arguments[3] === "function") {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(0) : "It looks like you are passing several store enhancers to createStore(). This is not supported. Instead, compose them together to a single function. See https://redux.js.org/tutorials/fundamentals/part-4-store#creating-a-store-with-enhancers for an example.");
  }
  if (typeof preloadedState === "function" && typeof enhancer === "undefined") {
    enhancer = preloadedState;
    preloadedState = void 0;
  }
  if (typeof enhancer !== "undefined") {
    if (typeof enhancer !== "function") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(1) : `Expected the enhancer to be a function. Instead, received: '${kindOf(enhancer)}'`);
    }
    return enhancer(createStore)(reducer, preloadedState);
  }
  let currentReducer = reducer;
  let currentState = preloadedState;
  let currentListeners = /* @__PURE__ */ new Map();
  let nextListeners = currentListeners;
  let listenerIdCounter = 0;
  let isDispatching = false;
  function ensureCanMutateNextListeners() {
    if (nextListeners === currentListeners) {
      nextListeners = /* @__PURE__ */ new Map();
      currentListeners.forEach((listener, key) => {
        nextListeners.set(key, listener);
      });
    }
  }
  function getState() {
    if (isDispatching) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(3) : "You may not call store.getState() while the reducer is executing. The reducer has already received the state as an argument. Pass it down from the top reducer instead of reading it from the store.");
    }
    return currentState;
  }
  function subscribe(listener) {
    if (typeof listener !== "function") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(4) : `Expected the listener to be a function. Instead, received: '${kindOf(listener)}'`);
    }
    if (isDispatching) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(5) : "You may not call store.subscribe() while the reducer is executing. If you would like to be notified after the store has been updated, subscribe from a component and invoke store.getState() in the callback to access the latest state. See https://redux.js.org/api/store#subscribelistener for more details.");
    }
    let isSubscribed = true;
    ensureCanMutateNextListeners();
    const listenerId = listenerIdCounter++;
    nextListeners.set(listenerId, listener);
    return function unsubscribe() {
      if (!isSubscribed) {
        return;
      }
      if (isDispatching) {
        throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(6) : "You may not unsubscribe from a store listener while the reducer is executing. See https://redux.js.org/api/store#subscribelistener for more details.");
      }
      isSubscribed = false;
      ensureCanMutateNextListeners();
      nextListeners.delete(listenerId);
      currentListeners = null;
    };
  }
  function dispatch(action) {
    if (!isPlainObject$1(action)) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(7) : `Actions must be plain objects. Instead, the actual type was: '${kindOf(action)}'. You may need to add middleware to your store setup to handle dispatching other values, such as 'redux-thunk' to handle dispatching functions. See https://redux.js.org/tutorials/fundamentals/part-4-store#middleware and https://redux.js.org/tutorials/fundamentals/part-6-async-logic#using-the-redux-thunk-middleware for examples.`);
    }
    if (typeof action.type === "undefined") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(8) : 'Actions may not have an undefined "type" property. You may have misspelled an action type string constant.');
    }
    if (typeof action.type !== "string") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(17) : `Action "type" property must be a string. Instead, the actual type was: '${kindOf(action.type)}'. Value was: '${action.type}' (stringified)`);
    }
    if (isDispatching) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(9) : "Reducers may not dispatch actions.");
    }
    try {
      isDispatching = true;
      currentState = currentReducer(currentState, action);
    } finally {
      isDispatching = false;
    }
    const listeners = currentListeners = nextListeners;
    listeners.forEach((listener) => {
      listener();
    });
    return action;
  }
  function replaceReducer(nextReducer) {
    if (typeof nextReducer !== "function") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(10) : `Expected the nextReducer to be a function. Instead, received: '${kindOf(nextReducer)}`);
    }
    currentReducer = nextReducer;
    dispatch({
      type: actionTypes_default.REPLACE
    });
  }
  function observable() {
    const outerSubscribe = subscribe;
    return {
      /**
       * The minimal observable subscription method.
       * @param observer Any object that can be used as an observer.
       * The observer object should have a `next` method.
       * @returns An object with an `unsubscribe` method that can
       * be used to unsubscribe the observable from the store, and prevent further
       * emission of values from the observable.
       */
      subscribe(observer) {
        if (typeof observer !== "object" || observer === null) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(11) : `Expected the observer to be an object. Instead, received: '${kindOf(observer)}'`);
        }
        function observeState() {
          const observerAsObserver = observer;
          if (observerAsObserver.next) {
            observerAsObserver.next(getState());
          }
        }
        observeState();
        const unsubscribe = outerSubscribe(observeState);
        return {
          unsubscribe
        };
      },
      [symbol_observable_default]() {
        return this;
      }
    };
  }
  dispatch({
    type: actionTypes_default.INIT
  });
  const store = {
    dispatch,
    subscribe,
    getState,
    replaceReducer,
    [symbol_observable_default]: observable
  };
  return store;
}

// src/utils/warning.ts
function warning(message) {
  if (typeof console !== "undefined" && typeof console.error === "function") {
    console.error(message);
  }
  try {
    throw new Error(message);
  } catch (e) {
  }
}

// src/combineReducers.ts
function getUnexpectedStateShapeWarningMessage(inputState, reducers, action, unexpectedKeyCache) {
  const reducerKeys = Object.keys(reducers);
  const argumentName = action && action.type === actionTypes_default.INIT ? "preloadedState argument passed to createStore" : "previous state received by the reducer";
  if (reducerKeys.length === 0) {
    return "Store does not have a valid reducer. Make sure the argument passed to combineReducers is an object whose values are reducers.";
  }
  if (!isPlainObject$1(inputState)) {
    return `The ${argumentName} has unexpected type of "${kindOf(inputState)}". Expected argument to be an object with the following keys: "${reducerKeys.join('", "')}"`;
  }
  const unexpectedKeys = Object.keys(inputState).filter((key) => !reducers.hasOwnProperty(key) && !unexpectedKeyCache[key]);
  unexpectedKeys.forEach((key) => {
    unexpectedKeyCache[key] = true;
  });
  if (action && action.type === actionTypes_default.REPLACE)
    return;
  if (unexpectedKeys.length > 0) {
    return `Unexpected ${unexpectedKeys.length > 1 ? "keys" : "key"} "${unexpectedKeys.join('", "')}" found in ${argumentName}. Expected to find one of the known reducer keys instead: "${reducerKeys.join('", "')}". Unexpected keys will be ignored.`;
  }
}
function assertReducerShape(reducers) {
  Object.keys(reducers).forEach((key) => {
    const reducer = reducers[key];
    const initialState = reducer(void 0, {
      type: actionTypes_default.INIT
    });
    if (typeof initialState === "undefined") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(12) : `The slice reducer for key "${key}" returned undefined during initialization. If the state passed to the reducer is undefined, you must explicitly return the initial state. The initial state may not be undefined. If you don't want to set a value for this reducer, you can use null instead of undefined.`);
    }
    if (typeof reducer(void 0, {
      type: actionTypes_default.PROBE_UNKNOWN_ACTION()
    }) === "undefined") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(13) : `The slice reducer for key "${key}" returned undefined when probed with a random type. Don't try to handle '${actionTypes_default.INIT}' or other actions in "redux/*" namespace. They are considered private. Instead, you must return the current state for any unknown actions, unless it is undefined, in which case you must return the initial state, regardless of the action type. The initial state may not be undefined, but can be null.`);
    }
  });
}
function combineReducers(reducers) {
  const reducerKeys = Object.keys(reducers);
  const finalReducers = {};
  for (let i = 0; i < reducerKeys.length; i++) {
    const key = reducerKeys[i];
    if (process.env.NODE_ENV !== "production") {
      if (typeof reducers[key] === "undefined") {
        warning(`No reducer provided for key "${key}"`);
      }
    }
    if (typeof reducers[key] === "function") {
      finalReducers[key] = reducers[key];
    }
  }
  const finalReducerKeys = Object.keys(finalReducers);
  let unexpectedKeyCache;
  if (process.env.NODE_ENV !== "production") {
    unexpectedKeyCache = {};
  }
  let shapeAssertionError;
  try {
    assertReducerShape(finalReducers);
  } catch (e) {
    shapeAssertionError = e;
  }
  return function combination(state = {}, action) {
    if (shapeAssertionError) {
      throw shapeAssertionError;
    }
    if (process.env.NODE_ENV !== "production") {
      const warningMessage = getUnexpectedStateShapeWarningMessage(state, finalReducers, action, unexpectedKeyCache);
      if (warningMessage) {
        warning(warningMessage);
      }
    }
    let hasChanged = false;
    const nextState = {};
    for (let i = 0; i < finalReducerKeys.length; i++) {
      const key = finalReducerKeys[i];
      const reducer = finalReducers[key];
      const previousStateForKey = state[key];
      const nextStateForKey = reducer(previousStateForKey, action);
      if (typeof nextStateForKey === "undefined") {
        const actionType = action && action.type;
        throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(14) : `When called with an action of type ${actionType ? `"${String(actionType)}"` : "(unknown type)"}, the slice reducer for key "${key}" returned undefined. To ignore an action, you must explicitly return the previous state. If you want this reducer to hold no value, you can return null instead of undefined.`);
      }
      nextState[key] = nextStateForKey;
      hasChanged = hasChanged || nextStateForKey !== previousStateForKey;
    }
    hasChanged = hasChanged || finalReducerKeys.length !== Object.keys(state).length;
    return hasChanged ? nextState : state;
  };
}

// src/compose.ts
function compose(...funcs) {
  if (funcs.length === 0) {
    return (arg) => arg;
  }
  if (funcs.length === 1) {
    return funcs[0];
  }
  return funcs.reduce((a, b) => (...args) => a(b(...args)));
}

// src/applyMiddleware.ts
function applyMiddleware(...middlewares) {
  return (createStore2) => (reducer, preloadedState) => {
    const store = createStore2(reducer, preloadedState);
    let dispatch = () => {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage$1(15) : "Dispatching while constructing your middleware is not allowed. Other middleware would not be applied to this dispatch.");
    };
    const middlewareAPI = {
      getState: store.getState,
      dispatch: (action, ...args) => dispatch(action, ...args)
    };
    const chain = middlewares.map((middleware) => middleware(middlewareAPI));
    dispatch = compose(...chain)(store.dispatch);
    return {
      ...store,
      dispatch
    };
  };
}

// src/utils/isAction.ts
function isAction(action) {
  return isPlainObject$1(action) && "type" in action && typeof action.type === "string";
}

// src/utils/env.ts
var NOTHING = Symbol.for("immer-nothing");
var DRAFTABLE = Symbol.for("immer-draftable");
var DRAFT_STATE = Symbol.for("immer-state");

// src/utils/errors.ts
var errors = process.env.NODE_ENV !== "production" ? [
  // All error codes, starting by 0:
  function(plugin) {
    return `The plugin for '${plugin}' has not been loaded into Immer. To enable the plugin, import and call \`enable${plugin}()\` when initializing your application.`;
  },
  function(thing) {
    return `produce can only be called on things that are draftable: plain objects, arrays, Map, Set or classes that are marked with '[immerable]: true'. Got '${thing}'`;
  },
  "This object has been frozen and should not be mutated",
  function(data) {
    return "Cannot use a proxy that has been revoked. Did you pass an object from inside an immer function to an async process? " + data;
  },
  "An immer producer returned a new value *and* modified its draft. Either return a new value *or* modify the draft.",
  "Immer forbids circular references",
  "The first or second argument to `produce` must be a function",
  "The third argument to `produce` must be a function or undefined",
  "First argument to `createDraft` must be a plain object, an array, or an immerable object",
  "First argument to `finishDraft` must be a draft returned by `createDraft`",
  function(thing) {
    return `'current' expects a draft, got: ${thing}`;
  },
  "Object.defineProperty() cannot be used on an Immer draft",
  "Object.setPrototypeOf() cannot be used on an Immer draft",
  "Immer only supports deleting array indices",
  "Immer only supports setting array indices and the 'length' property",
  function(thing) {
    return `'original' expects a draft, got: ${thing}`;
  }
  // Note: if more errors are added, the errorOffset in Patches.ts should be increased
  // See Patches.ts for additional errors
] : [];
function die(error, ...args) {
  if (process.env.NODE_ENV !== "production") {
    const e = errors[error];
    const msg = typeof e === "function" ? e.apply(null, args) : e;
    throw new Error(`[Immer] ${msg}`);
  }
  throw new Error(
    `[Immer] minified error nr: ${error}. Full error at: https://bit.ly/3cXEKWf`
  );
}

// src/utils/common.ts
var getPrototypeOf = Object.getPrototypeOf;
function isDraft(value) {
  return !!value && !!value[DRAFT_STATE];
}
function isDraftable(value) {
  if (!value)
    return false;
  return isPlainObject(value) || Array.isArray(value) || !!value[DRAFTABLE] || !!value.constructor?.[DRAFTABLE] || isMap(value) || isSet(value);
}
var objectCtorString = Object.prototype.constructor.toString();
function isPlainObject(value) {
  if (!value || typeof value !== "object")
    return false;
  const proto = getPrototypeOf(value);
  if (proto === null) {
    return true;
  }
  const Ctor = Object.hasOwnProperty.call(proto, "constructor") && proto.constructor;
  if (Ctor === Object)
    return true;
  return typeof Ctor == "function" && Function.toString.call(Ctor) === objectCtorString;
}
function each(obj, iter) {
  if (getArchtype(obj) === 0 /* Object */) {
    Reflect.ownKeys(obj).forEach((key) => {
      iter(key, obj[key], obj);
    });
  } else {
    obj.forEach((entry, index) => iter(index, entry, obj));
  }
}
function getArchtype(thing) {
  const state = thing[DRAFT_STATE];
  return state ? state.type_ : Array.isArray(thing) ? 1 /* Array */ : isMap(thing) ? 2 /* Map */ : isSet(thing) ? 3 /* Set */ : 0 /* Object */;
}
function has(thing, prop) {
  return getArchtype(thing) === 2 /* Map */ ? thing.has(prop) : Object.prototype.hasOwnProperty.call(thing, prop);
}
function set(thing, propOrOldValue, value) {
  const t = getArchtype(thing);
  if (t === 2 /* Map */)
    thing.set(propOrOldValue, value);
  else if (t === 3 /* Set */) {
    thing.add(value);
  } else
    thing[propOrOldValue] = value;
}
function is(x, y) {
  if (x === y) {
    return x !== 0 || 1 / x === 1 / y;
  } else {
    return x !== x && y !== y;
  }
}
function isMap(target) {
  return target instanceof Map;
}
function isSet(target) {
  return target instanceof Set;
}
function latest(state) {
  return state.copy_ || state.base_;
}
function shallowCopy(base, strict) {
  if (isMap(base)) {
    return new Map(base);
  }
  if (isSet(base)) {
    return new Set(base);
  }
  if (Array.isArray(base))
    return Array.prototype.slice.call(base);
  const isPlain = isPlainObject(base);
  if (strict === true || strict === "class_only" && !isPlain) {
    const descriptors = Object.getOwnPropertyDescriptors(base);
    delete descriptors[DRAFT_STATE];
    let keys = Reflect.ownKeys(descriptors);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      const desc = descriptors[key];
      if (desc.writable === false) {
        desc.writable = true;
        desc.configurable = true;
      }
      if (desc.get || desc.set)
        descriptors[key] = {
          configurable: true,
          writable: true,
          // could live with !!desc.set as well here...
          enumerable: desc.enumerable,
          value: base[key]
        };
    }
    return Object.create(getPrototypeOf(base), descriptors);
  } else {
    const proto = getPrototypeOf(base);
    if (proto !== null && isPlain) {
      return { ...base };
    }
    const obj = Object.create(proto);
    return Object.assign(obj, base);
  }
}
function freeze(obj, deep = false) {
  if (isFrozen(obj) || isDraft(obj) || !isDraftable(obj))
    return obj;
  if (getArchtype(obj) > 1) {
    obj.set = obj.add = obj.clear = obj.delete = dontMutateFrozenCollections;
  }
  Object.freeze(obj);
  if (deep)
    Object.entries(obj).forEach(([key, value]) => freeze(value, true));
  return obj;
}
function dontMutateFrozenCollections() {
  die(2);
}
function isFrozen(obj) {
  return Object.isFrozen(obj);
}

// src/utils/plugins.ts
var plugins = {};
function getPlugin(pluginKey) {
  const plugin = plugins[pluginKey];
  if (!plugin) {
    die(0, pluginKey);
  }
  return plugin;
}

// src/core/scope.ts
var currentScope;
function getCurrentScope() {
  return currentScope;
}
function createScope(parent_, immer_) {
  return {
    drafts_: [],
    parent_,
    immer_,
    // Whenever the modified draft contains a draft from another scope, we
    // need to prevent auto-freezing so the unowned draft can be finalized.
    canAutoFreeze_: true,
    unfinalizedDrafts_: 0
  };
}
function usePatchesInScope(scope, patchListener) {
  if (patchListener) {
    getPlugin("Patches");
    scope.patches_ = [];
    scope.inversePatches_ = [];
    scope.patchListener_ = patchListener;
  }
}
function revokeScope(scope) {
  leaveScope(scope);
  scope.drafts_.forEach(revokeDraft);
  scope.drafts_ = null;
}
function leaveScope(scope) {
  if (scope === currentScope) {
    currentScope = scope.parent_;
  }
}
function enterScope(immer2) {
  return currentScope = createScope(currentScope, immer2);
}
function revokeDraft(draft) {
  const state = draft[DRAFT_STATE];
  if (state.type_ === 0 /* Object */ || state.type_ === 1 /* Array */)
    state.revoke_();
  else
    state.revoked_ = true;
}

// src/core/finalize.ts
function processResult(result, scope) {
  scope.unfinalizedDrafts_ = scope.drafts_.length;
  const baseDraft = scope.drafts_[0];
  const isReplaced = result !== void 0 && result !== baseDraft;
  if (isReplaced) {
    if (baseDraft[DRAFT_STATE].modified_) {
      revokeScope(scope);
      die(4);
    }
    if (isDraftable(result)) {
      result = finalize(scope, result);
      if (!scope.parent_)
        maybeFreeze(scope, result);
    }
    if (scope.patches_) {
      getPlugin("Patches").generateReplacementPatches_(
        baseDraft[DRAFT_STATE].base_,
        result,
        scope.patches_,
        scope.inversePatches_
      );
    }
  } else {
    result = finalize(scope, baseDraft, []);
  }
  revokeScope(scope);
  if (scope.patches_) {
    scope.patchListener_(scope.patches_, scope.inversePatches_);
  }
  return result !== NOTHING ? result : void 0;
}
function finalize(rootScope, value, path) {
  if (isFrozen(value))
    return value;
  const state = value[DRAFT_STATE];
  if (!state) {
    each(
      value,
      (key, childValue) => finalizeProperty(rootScope, state, value, key, childValue, path)
    );
    return value;
  }
  if (state.scope_ !== rootScope)
    return value;
  if (!state.modified_) {
    maybeFreeze(rootScope, state.base_, true);
    return state.base_;
  }
  if (!state.finalized_) {
    state.finalized_ = true;
    state.scope_.unfinalizedDrafts_--;
    const result = state.copy_;
    let resultEach = result;
    let isSet2 = false;
    if (state.type_ === 3 /* Set */) {
      resultEach = new Set(result);
      result.clear();
      isSet2 = true;
    }
    each(
      resultEach,
      (key, childValue) => finalizeProperty(rootScope, state, result, key, childValue, path, isSet2)
    );
    maybeFreeze(rootScope, result, false);
    if (path && rootScope.patches_) {
      getPlugin("Patches").generatePatches_(
        state,
        path,
        rootScope.patches_,
        rootScope.inversePatches_
      );
    }
  }
  return state.copy_;
}
function finalizeProperty(rootScope, parentState, targetObject, prop, childValue, rootPath, targetIsSet) {
  if (process.env.NODE_ENV !== "production" && childValue === targetObject)
    die(5);
  if (isDraft(childValue)) {
    const path = rootPath && parentState && parentState.type_ !== 3 /* Set */ && // Set objects are atomic since they have no keys.
    !has(parentState.assigned_, prop) ? rootPath.concat(prop) : void 0;
    const res = finalize(rootScope, childValue, path);
    set(targetObject, prop, res);
    if (isDraft(res)) {
      rootScope.canAutoFreeze_ = false;
    } else
      return;
  } else if (targetIsSet) {
    targetObject.add(childValue);
  }
  if (isDraftable(childValue) && !isFrozen(childValue)) {
    if (!rootScope.immer_.autoFreeze_ && rootScope.unfinalizedDrafts_ < 1) {
      return;
    }
    finalize(rootScope, childValue);
    if ((!parentState || !parentState.scope_.parent_) && typeof prop !== "symbol" && Object.prototype.propertyIsEnumerable.call(targetObject, prop))
      maybeFreeze(rootScope, childValue);
  }
}
function maybeFreeze(scope, value, deep = false) {
  if (!scope.parent_ && scope.immer_.autoFreeze_ && scope.canAutoFreeze_) {
    freeze(value, deep);
  }
}

// src/core/proxy.ts
function createProxyProxy(base, parent) {
  const isArray = Array.isArray(base);
  const state = {
    type_: isArray ? 1 /* Array */ : 0 /* Object */,
    // Track which produce call this is associated with.
    scope_: parent ? parent.scope_ : getCurrentScope(),
    // True for both shallow and deep changes.
    modified_: false,
    // Used during finalization.
    finalized_: false,
    // Track which properties have been assigned (true) or deleted (false).
    assigned_: {},
    // The parent draft state.
    parent_: parent,
    // The base state.
    base_: base,
    // The base proxy.
    draft_: null,
    // set below
    // The base copy with any updated values.
    copy_: null,
    // Called by the `produce` function.
    revoke_: null,
    isManual_: false
  };
  let target = state;
  let traps = objectTraps;
  if (isArray) {
    target = [state];
    traps = arrayTraps;
  }
  const { revoke, proxy } = Proxy.revocable(target, traps);
  state.draft_ = proxy;
  state.revoke_ = revoke;
  return proxy;
}
var objectTraps = {
  get(state, prop) {
    if (prop === DRAFT_STATE)
      return state;
    const source = latest(state);
    if (!has(source, prop)) {
      return readPropFromProto(state, source, prop);
    }
    const value = source[prop];
    if (state.finalized_ || !isDraftable(value)) {
      return value;
    }
    if (value === peek(state.base_, prop)) {
      prepareCopy(state);
      return state.copy_[prop] = createProxy(value, state);
    }
    return value;
  },
  has(state, prop) {
    return prop in latest(state);
  },
  ownKeys(state) {
    return Reflect.ownKeys(latest(state));
  },
  set(state, prop, value) {
    const desc = getDescriptorFromProto(latest(state), prop);
    if (desc?.set) {
      desc.set.call(state.draft_, value);
      return true;
    }
    if (!state.modified_) {
      const current2 = peek(latest(state), prop);
      const currentState = current2?.[DRAFT_STATE];
      if (currentState && currentState.base_ === value) {
        state.copy_[prop] = value;
        state.assigned_[prop] = false;
        return true;
      }
      if (is(value, current2) && (value !== void 0 || has(state.base_, prop)))
        return true;
      prepareCopy(state);
      markChanged(state);
    }
    if (state.copy_[prop] === value && // special case: handle new props with value 'undefined'
    (value !== void 0 || prop in state.copy_) || // special case: NaN
    Number.isNaN(value) && Number.isNaN(state.copy_[prop]))
      return true;
    state.copy_[prop] = value;
    state.assigned_[prop] = true;
    return true;
  },
  deleteProperty(state, prop) {
    if (peek(state.base_, prop) !== void 0 || prop in state.base_) {
      state.assigned_[prop] = false;
      prepareCopy(state);
      markChanged(state);
    } else {
      delete state.assigned_[prop];
    }
    if (state.copy_) {
      delete state.copy_[prop];
    }
    return true;
  },
  // Note: We never coerce `desc.value` into an Immer draft, because we can't make
  // the same guarantee in ES5 mode.
  getOwnPropertyDescriptor(state, prop) {
    const owner = latest(state);
    const desc = Reflect.getOwnPropertyDescriptor(owner, prop);
    if (!desc)
      return desc;
    return {
      writable: true,
      configurable: state.type_ !== 1 /* Array */ || prop !== "length",
      enumerable: desc.enumerable,
      value: owner[prop]
    };
  },
  defineProperty() {
    die(11);
  },
  getPrototypeOf(state) {
    return getPrototypeOf(state.base_);
  },
  setPrototypeOf() {
    die(12);
  }
};
var arrayTraps = {};
each(objectTraps, (key, fn) => {
  arrayTraps[key] = function() {
    arguments[0] = arguments[0][0];
    return fn.apply(this, arguments);
  };
});
arrayTraps.deleteProperty = function(state, prop) {
  if (process.env.NODE_ENV !== "production" && isNaN(parseInt(prop)))
    die(13);
  return arrayTraps.set.call(this, state, prop, void 0);
};
arrayTraps.set = function(state, prop, value) {
  if (process.env.NODE_ENV !== "production" && prop !== "length" && isNaN(parseInt(prop)))
    die(14);
  return objectTraps.set.call(this, state[0], prop, value, state[0]);
};
function peek(draft, prop) {
  const state = draft[DRAFT_STATE];
  const source = state ? latest(state) : draft;
  return source[prop];
}
function readPropFromProto(state, source, prop) {
  const desc = getDescriptorFromProto(source, prop);
  return desc ? `value` in desc ? desc.value : (
    // This is a very special case, if the prop is a getter defined by the
    // prototype, we should invoke it with the draft as context!
    desc.get?.call(state.draft_)
  ) : void 0;
}
function getDescriptorFromProto(source, prop) {
  if (!(prop in source))
    return void 0;
  let proto = getPrototypeOf(source);
  while (proto) {
    const desc = Object.getOwnPropertyDescriptor(proto, prop);
    if (desc)
      return desc;
    proto = getPrototypeOf(proto);
  }
  return void 0;
}
function markChanged(state) {
  if (!state.modified_) {
    state.modified_ = true;
    if (state.parent_) {
      markChanged(state.parent_);
    }
  }
}
function prepareCopy(state) {
  if (!state.copy_) {
    state.copy_ = shallowCopy(
      state.base_,
      state.scope_.immer_.useStrictShallowCopy_
    );
  }
}

// src/core/immerClass.ts
var Immer2 = class {
  constructor(config) {
    this.autoFreeze_ = true;
    this.useStrictShallowCopy_ = false;
    /**
     * The `produce` function takes a value and a "recipe function" (whose
     * return value often depends on the base state). The recipe function is
     * free to mutate its first argument however it wants. All mutations are
     * only ever applied to a __copy__ of the base state.
     *
     * Pass only a function to create a "curried producer" which relieves you
     * from passing the recipe function every time.
     *
     * Only plain objects and arrays are made mutable. All other objects are
     * considered uncopyable.
     *
     * Note: This function is __bound__ to its `Immer` instance.
     *
     * @param {any} base - the initial state
     * @param {Function} recipe - function that receives a proxy of the base state as first argument and which can be freely modified
     * @param {Function} patchListener - optional function that will be called with all the patches produced here
     * @returns {any} a new state, or the initial state if nothing was modified
     */
    this.produce = (base, recipe, patchListener) => {
      if (typeof base === "function" && typeof recipe !== "function") {
        const defaultBase = recipe;
        recipe = base;
        const self = this;
        return function curriedProduce(base2 = defaultBase, ...args) {
          return self.produce(base2, (draft) => recipe.call(this, draft, ...args));
        };
      }
      if (typeof recipe !== "function")
        die(6);
      if (patchListener !== void 0 && typeof patchListener !== "function")
        die(7);
      let result;
      if (isDraftable(base)) {
        const scope = enterScope(this);
        const proxy = createProxy(base, void 0);
        let hasError = true;
        try {
          result = recipe(proxy);
          hasError = false;
        } finally {
          if (hasError)
            revokeScope(scope);
          else
            leaveScope(scope);
        }
        usePatchesInScope(scope, patchListener);
        return processResult(result, scope);
      } else if (!base || typeof base !== "object") {
        result = recipe(base);
        if (result === void 0)
          result = base;
        if (result === NOTHING)
          result = void 0;
        if (this.autoFreeze_)
          freeze(result, true);
        if (patchListener) {
          const p = [];
          const ip = [];
          getPlugin("Patches").generateReplacementPatches_(base, result, p, ip);
          patchListener(p, ip);
        }
        return result;
      } else
        die(1, base);
    };
    this.produceWithPatches = (base, recipe) => {
      if (typeof base === "function") {
        return (state, ...args) => this.produceWithPatches(state, (draft) => base(draft, ...args));
      }
      let patches, inversePatches;
      const result = this.produce(base, recipe, (p, ip) => {
        patches = p;
        inversePatches = ip;
      });
      return [result, patches, inversePatches];
    };
    if (typeof config?.autoFreeze === "boolean")
      this.setAutoFreeze(config.autoFreeze);
    if (typeof config?.useStrictShallowCopy === "boolean")
      this.setUseStrictShallowCopy(config.useStrictShallowCopy);
  }
  createDraft(base) {
    if (!isDraftable(base))
      die(8);
    if (isDraft(base))
      base = current(base);
    const scope = enterScope(this);
    const proxy = createProxy(base, void 0);
    proxy[DRAFT_STATE].isManual_ = true;
    leaveScope(scope);
    return proxy;
  }
  finishDraft(draft, patchListener) {
    const state = draft && draft[DRAFT_STATE];
    if (!state || !state.isManual_)
      die(9);
    const { scope_: scope } = state;
    usePatchesInScope(scope, patchListener);
    return processResult(void 0, scope);
  }
  /**
   * Pass true to automatically freeze all copies created by Immer.
   *
   * By default, auto-freezing is enabled.
   */
  setAutoFreeze(value) {
    this.autoFreeze_ = value;
  }
  /**
   * Pass true to enable strict shallow copy.
   *
   * By default, immer does not copy the object descriptors such as getter, setter and non-enumrable properties.
   */
  setUseStrictShallowCopy(value) {
    this.useStrictShallowCopy_ = value;
  }
  applyPatches(base, patches) {
    let i;
    for (i = patches.length - 1; i >= 0; i--) {
      const patch = patches[i];
      if (patch.path.length === 0 && patch.op === "replace") {
        base = patch.value;
        break;
      }
    }
    if (i > -1) {
      patches = patches.slice(i + 1);
    }
    const applyPatchesImpl = getPlugin("Patches").applyPatches_;
    if (isDraft(base)) {
      return applyPatchesImpl(base, patches);
    }
    return this.produce(
      base,
      (draft) => applyPatchesImpl(draft, patches)
    );
  }
};
function createProxy(value, parent) {
  const draft = isMap(value) ? getPlugin("MapSet").proxyMap_(value, parent) : isSet(value) ? getPlugin("MapSet").proxySet_(value, parent) : createProxyProxy(value, parent);
  const scope = parent ? parent.scope_ : getCurrentScope();
  scope.drafts_.push(draft);
  return draft;
}

// src/core/current.ts
function current(value) {
  if (!isDraft(value))
    die(10, value);
  return currentImpl(value);
}
function currentImpl(value) {
  if (!isDraftable(value) || isFrozen(value))
    return value;
  const state = value[DRAFT_STATE];
  let copy;
  if (state) {
    if (!state.modified_)
      return state.base_;
    state.finalized_ = true;
    copy = shallowCopy(value, state.scope_.immer_.useStrictShallowCopy_);
  } else {
    copy = shallowCopy(value, true);
  }
  each(copy, (key, childValue) => {
    set(copy, key, currentImpl(childValue));
  });
  if (state) {
    state.finalized_ = false;
  }
  return copy;
}

// src/immer.ts
var immer = new Immer2();
var produce = immer.produce;
immer.produceWithPatches.bind(
  immer
);
immer.setAutoFreeze.bind(immer);
immer.setUseStrictShallowCopy.bind(immer);
immer.applyPatches.bind(immer);
immer.createDraft.bind(immer);
immer.finishDraft.bind(immer);

// src/index.ts
function createThunkMiddleware(extraArgument) {
  const middleware = ({ dispatch, getState }) => (next) => (action) => {
    if (typeof action === "function") {
      return action(dispatch, getState, extraArgument);
    }
    return next(action);
  };
  return middleware;
}
var thunk = createThunkMiddleware();
var withExtraArgument = createThunkMiddleware;

// src/index.ts
var composeWithDevTools = typeof window !== "undefined" && window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__ ? window.__REDUX_DEVTOOLS_EXTENSION_COMPOSE__ : function() {
  if (arguments.length === 0) return void 0;
  if (typeof arguments[0] === "object") return compose;
  return compose.apply(null, arguments);
};

// src/tsHelpers.ts
var hasMatchFunction = (v) => {
  return v && typeof v.match === "function";
};

// src/createAction.ts
function createAction(type, prepareAction) {
  function actionCreator(...args) {
    if (prepareAction) {
      let prepared = prepareAction(...args);
      if (!prepared) {
        throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(0) : "prepareAction did not return an object");
      }
      return {
        type,
        payload: prepared.payload,
        ..."meta" in prepared && {
          meta: prepared.meta
        },
        ..."error" in prepared && {
          error: prepared.error
        }
      };
    }
    return {
      type,
      payload: args[0]
    };
  }
  actionCreator.toString = () => `${type}`;
  actionCreator.type = type;
  actionCreator.match = (action) => isAction(action) && action.type === type;
  return actionCreator;
}
function isActionCreator(action) {
  return typeof action === "function" && "type" in action && // hasMatchFunction only wants Matchers but I don't see the point in rewriting it
  hasMatchFunction(action);
}

// src/actionCreatorInvariantMiddleware.ts
function getMessage(type) {
  const splitType = type ? `${type}`.split("/") : [];
  const actionName = splitType[splitType.length - 1] || "actionCreator";
  return `Detected an action creator with type "${type || "unknown"}" being dispatched. 
Make sure you're calling the action creator before dispatching, i.e. \`dispatch(${actionName}())\` instead of \`dispatch(${actionName})\`. This is necessary even if the action has no payload.`;
}
function createActionCreatorInvariantMiddleware(options = {}) {
  if (process.env.NODE_ENV === "production") {
    return () => (next) => (action) => next(action);
  }
  const {
    isActionCreator: isActionCreator2 = isActionCreator
  } = options;
  return () => (next) => (action) => {
    if (isActionCreator2(action)) {
      console.warn(getMessage(action.type));
    }
    return next(action);
  };
}
function getTimeMeasureUtils(maxDelay, fnName) {
  let elapsed = 0;
  return {
    measureTime(fn) {
      const started = Date.now();
      try {
        return fn();
      } finally {
        const finished = Date.now();
        elapsed += finished - started;
      }
    },
    warnIfExceeded() {
      if (elapsed > maxDelay) {
        console.warn(`${fnName} took ${elapsed}ms, which is more than the warning threshold of ${maxDelay}ms. 
If your state or actions are very large, you may want to disable the middleware as it might cause too much of a slowdown in development mode. See https://redux-toolkit.js.org/api/getDefaultMiddleware for instructions.
It is disabled in production builds, so you don't need to worry about that.`);
      }
    }
  };
}
var Tuple = class _Tuple extends Array {
  constructor(...items) {
    super(...items);
    Object.setPrototypeOf(this, _Tuple.prototype);
  }
  static get [Symbol.species]() {
    return _Tuple;
  }
  concat(...arr) {
    return super.concat.apply(this, arr);
  }
  prepend(...arr) {
    if (arr.length === 1 && Array.isArray(arr[0])) {
      return new _Tuple(...arr[0].concat(this));
    }
    return new _Tuple(...arr.concat(this));
  }
};
function freezeDraftable(val) {
  return isDraftable(val) ? produce(val, () => {
  }) : val;
}
function emplace(map, key, handler) {
  if (map.has(key)) {
    let value = map.get(key);
    if (handler.update) {
      value = handler.update(value, key, map);
      map.set(key, value);
    }
    return value;
  }
  if (!handler.insert) throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(10) : "No insert provided for key not already in map");
  const inserted = handler.insert(key, map);
  map.set(key, inserted);
  return inserted;
}

// src/immutableStateInvariantMiddleware.ts
function isImmutableDefault(value) {
  return typeof value !== "object" || value == null || Object.isFrozen(value);
}
function trackForMutations(isImmutable, ignorePaths, obj) {
  const trackedProperties = trackProperties(isImmutable, ignorePaths, obj);
  return {
    detectMutations() {
      return detectMutations(isImmutable, ignorePaths, trackedProperties, obj);
    }
  };
}
function trackProperties(isImmutable, ignorePaths = [], obj, path = "", checkedObjects = /* @__PURE__ */ new Set()) {
  const tracked = {
    value: obj
  };
  if (!isImmutable(obj) && !checkedObjects.has(obj)) {
    checkedObjects.add(obj);
    tracked.children = {};
    for (const key in obj) {
      const childPath = path ? path + "." + key : key;
      if (ignorePaths.length && ignorePaths.indexOf(childPath) !== -1) {
        continue;
      }
      tracked.children[key] = trackProperties(isImmutable, ignorePaths, obj[key], childPath);
    }
  }
  return tracked;
}
function detectMutations(isImmutable, ignoredPaths = [], trackedProperty, obj, sameParentRef = false, path = "") {
  const prevObj = trackedProperty ? trackedProperty.value : void 0;
  const sameRef = prevObj === obj;
  if (sameParentRef && !sameRef && !Number.isNaN(obj)) {
    return {
      wasMutated: true,
      path
    };
  }
  if (isImmutable(prevObj) || isImmutable(obj)) {
    return {
      wasMutated: false
    };
  }
  const keysToDetect = {};
  for (let key in trackedProperty.children) {
    keysToDetect[key] = true;
  }
  for (let key in obj) {
    keysToDetect[key] = true;
  }
  const hasIgnoredPaths = ignoredPaths.length > 0;
  for (let key in keysToDetect) {
    const nestedPath = path ? path + "." + key : key;
    if (hasIgnoredPaths) {
      const hasMatches = ignoredPaths.some((ignored) => {
        if (ignored instanceof RegExp) {
          return ignored.test(nestedPath);
        }
        return nestedPath === ignored;
      });
      if (hasMatches) {
        continue;
      }
    }
    const result = detectMutations(isImmutable, ignoredPaths, trackedProperty.children[key], obj[key], sameRef, nestedPath);
    if (result.wasMutated) {
      return result;
    }
  }
  return {
    wasMutated: false
  };
}
function createImmutableStateInvariantMiddleware(options = {}) {
  if (process.env.NODE_ENV === "production") {
    return () => (next) => (action) => next(action);
  } else {
    let stringify2 = function(obj, serializer, indent, decycler) {
      return JSON.stringify(obj, getSerialize2(serializer, decycler), indent);
    }, getSerialize2 = function(serializer, decycler) {
      let stack = [], keys = [];
      if (!decycler) decycler = function(_, value) {
        if (stack[0] === value) return "[Circular ~]";
        return "[Circular ~." + keys.slice(0, stack.indexOf(value)).join(".") + "]";
      };
      return function(key, value) {
        if (stack.length > 0) {
          var thisPos = stack.indexOf(this);
          ~thisPos ? stack.splice(thisPos + 1) : stack.push(this);
          ~thisPos ? keys.splice(thisPos, Infinity, key) : keys.push(key);
          if (~stack.indexOf(value)) value = decycler.call(this, key, value);
        } else stack.push(value);
        return serializer == null ? value : serializer.call(this, key, value);
      };
    };
    let {
      isImmutable = isImmutableDefault,
      ignoredPaths,
      warnAfter = 32
    } = options;
    const track = trackForMutations.bind(null, isImmutable, ignoredPaths);
    return ({
      getState
    }) => {
      let state = getState();
      let tracker = track(state);
      let result;
      return (next) => (action) => {
        const measureUtils = getTimeMeasureUtils(warnAfter, "ImmutableStateInvariantMiddleware");
        measureUtils.measureTime(() => {
          state = getState();
          result = tracker.detectMutations();
          tracker = track(state);
          if (result.wasMutated) {
            throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(19) : `A state mutation was detected between dispatches, in the path '${result.path || ""}'.  This may cause incorrect behavior. (https://redux.js.org/style-guide/style-guide#do-not-mutate-state)`);
          }
        });
        const dispatchedAction = next(action);
        measureUtils.measureTime(() => {
          state = getState();
          result = tracker.detectMutations();
          tracker = track(state);
          if (result.wasMutated) {
            throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(20) : `A state mutation was detected inside a dispatch, in the path: ${result.path || ""}. Take a look at the reducer(s) handling the action ${stringify2(action)}. (https://redux.js.org/style-guide/style-guide#do-not-mutate-state)`);
          }
        });
        measureUtils.warnIfExceeded();
        return dispatchedAction;
      };
    };
  }
}
function isPlain(val) {
  const type = typeof val;
  return val == null || type === "string" || type === "boolean" || type === "number" || Array.isArray(val) || isPlainObject$1(val);
}
function findNonSerializableValue(value, path = "", isSerializable = isPlain, getEntries, ignoredPaths = [], cache) {
  let foundNestedSerializable;
  if (!isSerializable(value)) {
    return {
      keyPath: path || "<root>",
      value
    };
  }
  if (typeof value !== "object" || value === null) {
    return false;
  }
  if (cache?.has(value)) return false;
  const entries = getEntries != null ? getEntries(value) : Object.entries(value);
  const hasIgnoredPaths = ignoredPaths.length > 0;
  for (const [key, nestedValue] of entries) {
    const nestedPath = path ? path + "." + key : key;
    if (hasIgnoredPaths) {
      const hasMatches = ignoredPaths.some((ignored) => {
        if (ignored instanceof RegExp) {
          return ignored.test(nestedPath);
        }
        return nestedPath === ignored;
      });
      if (hasMatches) {
        continue;
      }
    }
    if (!isSerializable(nestedValue)) {
      return {
        keyPath: nestedPath,
        value: nestedValue
      };
    }
    if (typeof nestedValue === "object") {
      foundNestedSerializable = findNonSerializableValue(nestedValue, nestedPath, isSerializable, getEntries, ignoredPaths, cache);
      if (foundNestedSerializable) {
        return foundNestedSerializable;
      }
    }
  }
  if (cache && isNestedFrozen(value)) cache.add(value);
  return false;
}
function isNestedFrozen(value) {
  if (!Object.isFrozen(value)) return false;
  for (const nestedValue of Object.values(value)) {
    if (typeof nestedValue !== "object" || nestedValue === null) continue;
    if (!isNestedFrozen(nestedValue)) return false;
  }
  return true;
}
function createSerializableStateInvariantMiddleware(options = {}) {
  if (process.env.NODE_ENV === "production") {
    return () => (next) => (action) => next(action);
  } else {
    const {
      isSerializable = isPlain,
      getEntries,
      ignoredActions = [],
      ignoredActionPaths = ["meta.arg", "meta.baseQueryMeta"],
      ignoredPaths = [],
      warnAfter = 32,
      ignoreState = false,
      ignoreActions = false,
      disableCache = false
    } = options;
    const cache = !disableCache && WeakSet ? /* @__PURE__ */ new WeakSet() : void 0;
    return (storeAPI) => (next) => (action) => {
      if (!isAction(action)) {
        return next(action);
      }
      const result = next(action);
      const measureUtils = getTimeMeasureUtils(warnAfter, "SerializableStateInvariantMiddleware");
      if (!ignoreActions && !(ignoredActions.length && ignoredActions.indexOf(action.type) !== -1)) {
        measureUtils.measureTime(() => {
          const foundActionNonSerializableValue = findNonSerializableValue(action, "", isSerializable, getEntries, ignoredActionPaths, cache);
          if (foundActionNonSerializableValue) {
            const {
              keyPath,
              value
            } = foundActionNonSerializableValue;
            console.error(`A non-serializable value was detected in an action, in the path: \`${keyPath}\`. Value:`, value, "\nTake a look at the logic that dispatched this action: ", action, "\n(See https://redux.js.org/faq/actions#why-should-type-be-a-string-or-at-least-serializable-why-should-my-action-types-be-constants)", "\n(To allow non-serializable values see: https://redux-toolkit.js.org/usage/usage-guide#working-with-non-serializable-data)");
          }
        });
      }
      if (!ignoreState) {
        measureUtils.measureTime(() => {
          const state = storeAPI.getState();
          const foundStateNonSerializableValue = findNonSerializableValue(state, "", isSerializable, getEntries, ignoredPaths, cache);
          if (foundStateNonSerializableValue) {
            const {
              keyPath,
              value
            } = foundStateNonSerializableValue;
            console.error(`A non-serializable value was detected in the state, in the path: \`${keyPath}\`. Value:`, value, `
Take a look at the reducer(s) handling this action type: ${action.type}.
(See https://redux.js.org/faq/organizing-state#can-i-put-functions-promises-or-other-non-serializable-items-in-my-store-state)`);
          }
        });
        measureUtils.warnIfExceeded();
      }
      return result;
    };
  }
}

// src/getDefaultMiddleware.ts
function isBoolean(x) {
  return typeof x === "boolean";
}
var buildGetDefaultMiddleware = () => function getDefaultMiddleware(options) {
  const {
    thunk: thunk$1 = true,
    immutableCheck = true,
    serializableCheck = true,
    actionCreatorCheck = true
  } = options ?? {};
  let middlewareArray = new Tuple();
  if (thunk$1) {
    if (isBoolean(thunk$1)) {
      middlewareArray.push(thunk);
    } else {
      middlewareArray.push(withExtraArgument(thunk$1.extraArgument));
    }
  }
  if (process.env.NODE_ENV !== "production") {
    if (immutableCheck) {
      let immutableOptions = {};
      if (!isBoolean(immutableCheck)) {
        immutableOptions = immutableCheck;
      }
      middlewareArray.unshift(createImmutableStateInvariantMiddleware(immutableOptions));
    }
    if (serializableCheck) {
      let serializableOptions = {};
      if (!isBoolean(serializableCheck)) {
        serializableOptions = serializableCheck;
      }
      middlewareArray.push(createSerializableStateInvariantMiddleware(serializableOptions));
    }
    if (actionCreatorCheck) {
      let actionCreatorOptions = {};
      if (!isBoolean(actionCreatorCheck)) {
        actionCreatorOptions = actionCreatorCheck;
      }
      middlewareArray.unshift(createActionCreatorInvariantMiddleware(actionCreatorOptions));
    }
  }
  return middlewareArray;
};

// src/autoBatchEnhancer.ts
var SHOULD_AUTOBATCH = "RTK_autoBatch";
var createQueueWithTimer = (timeout) => {
  return (notify) => {
    setTimeout(notify, timeout);
  };
};
var rAF = typeof window !== "undefined" && window.requestAnimationFrame ? window.requestAnimationFrame : createQueueWithTimer(10);
var autoBatchEnhancer = (options = {
  type: "raf"
}) => (next) => (...args) => {
  const store = next(...args);
  let notifying = true;
  let shouldNotifyAtEndOfTick = false;
  let notificationQueued = false;
  const listeners = /* @__PURE__ */ new Set();
  const queueCallback = options.type === "tick" ? queueMicrotask : options.type === "raf" ? rAF : options.type === "callback" ? options.queueNotification : createQueueWithTimer(options.timeout);
  const notifyListeners = () => {
    notificationQueued = false;
    if (shouldNotifyAtEndOfTick) {
      shouldNotifyAtEndOfTick = false;
      listeners.forEach((l) => l());
    }
  };
  return Object.assign({}, store, {
    // Override the base `store.subscribe` method to keep original listeners
    // from running if we're delaying notifications
    subscribe(listener2) {
      const wrappedListener = () => notifying && listener2();
      const unsubscribe = store.subscribe(wrappedListener);
      listeners.add(listener2);
      return () => {
        unsubscribe();
        listeners.delete(listener2);
      };
    },
    // Override the base `store.dispatch` method so that we can check actions
    // for the `shouldAutoBatch` flag and determine if batching is active
    dispatch(action) {
      try {
        notifying = !action?.meta?.[SHOULD_AUTOBATCH];
        shouldNotifyAtEndOfTick = !notifying;
        if (shouldNotifyAtEndOfTick) {
          if (!notificationQueued) {
            notificationQueued = true;
            queueCallback(notifyListeners);
          }
        }
        return store.dispatch(action);
      } finally {
        notifying = true;
      }
    }
  });
};

// src/getDefaultEnhancers.ts
var buildGetDefaultEnhancers = (middlewareEnhancer) => function getDefaultEnhancers(options) {
  const {
    autoBatch = true
  } = options ?? {};
  let enhancerArray = new Tuple(middlewareEnhancer);
  if (autoBatch) {
    enhancerArray.push(autoBatchEnhancer(typeof autoBatch === "object" ? autoBatch : void 0));
  }
  return enhancerArray;
};

// src/configureStore.ts
function configureStore(options) {
  const getDefaultMiddleware = buildGetDefaultMiddleware();
  const {
    reducer = void 0,
    middleware,
    devTools = true,
    preloadedState = void 0,
    enhancers = void 0
  } = options || {};
  let rootReducer;
  if (typeof reducer === "function") {
    rootReducer = reducer;
  } else if (isPlainObject$1(reducer)) {
    rootReducer = combineReducers(reducer);
  } else {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(1) : "`reducer` is a required argument, and must be a function or an object of functions that can be passed to combineReducers");
  }
  if (process.env.NODE_ENV !== "production" && middleware && typeof middleware !== "function") {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(2) : "`middleware` field must be a callback");
  }
  let finalMiddleware;
  if (typeof middleware === "function") {
    finalMiddleware = middleware(getDefaultMiddleware);
    if (process.env.NODE_ENV !== "production" && !Array.isArray(finalMiddleware)) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(3) : "when using a middleware builder function, an array of middleware must be returned");
    }
  } else {
    finalMiddleware = getDefaultMiddleware();
  }
  if (process.env.NODE_ENV !== "production" && finalMiddleware.some((item) => typeof item !== "function")) {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(4) : "each middleware provided to configureStore must be a function");
  }
  let finalCompose = compose;
  if (devTools) {
    finalCompose = composeWithDevTools({
      // Enable capture of stack traces for dispatched Redux actions
      trace: process.env.NODE_ENV !== "production",
      ...typeof devTools === "object" && devTools
    });
  }
  const middlewareEnhancer = applyMiddleware(...finalMiddleware);
  const getDefaultEnhancers = buildGetDefaultEnhancers(middlewareEnhancer);
  if (process.env.NODE_ENV !== "production" && enhancers && typeof enhancers !== "function") {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(5) : "`enhancers` field must be a callback");
  }
  let storeEnhancers = typeof enhancers === "function" ? enhancers(getDefaultEnhancers) : getDefaultEnhancers();
  if (process.env.NODE_ENV !== "production" && !Array.isArray(storeEnhancers)) {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(6) : "`enhancers` callback must return an array");
  }
  if (process.env.NODE_ENV !== "production" && storeEnhancers.some((item) => typeof item !== "function")) {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(7) : "each enhancer provided to configureStore must be a function");
  }
  if (process.env.NODE_ENV !== "production" && finalMiddleware.length && !storeEnhancers.includes(middlewareEnhancer)) {
    console.error("middlewares were provided, but middleware enhancer was not included in final enhancers - make sure to call `getDefaultEnhancers`");
  }
  const composedEnhancer = finalCompose(...storeEnhancers);
  return createStore(rootReducer, preloadedState, composedEnhancer);
}

// src/mapBuilders.ts
function executeReducerBuilderCallback(builderCallback) {
  const actionsMap = {};
  const actionMatchers = [];
  let defaultCaseReducer;
  const builder = {
    addCase(typeOrActionCreator, reducer) {
      if (process.env.NODE_ENV !== "production") {
        if (actionMatchers.length > 0) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(26) : "`builder.addCase` should only be called before calling `builder.addMatcher`");
        }
        if (defaultCaseReducer) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(27) : "`builder.addCase` should only be called before calling `builder.addDefaultCase`");
        }
      }
      const type = typeof typeOrActionCreator === "string" ? typeOrActionCreator : typeOrActionCreator.type;
      if (!type) {
        throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(28) : "`builder.addCase` cannot be called with an empty action type");
      }
      if (type in actionsMap) {
        throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(29) : `\`builder.addCase\` cannot be called with two reducers for the same action type '${type}'`);
      }
      actionsMap[type] = reducer;
      return builder;
    },
    addMatcher(matcher, reducer) {
      if (process.env.NODE_ENV !== "production") {
        if (defaultCaseReducer) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(30) : "`builder.addMatcher` should only be called before calling `builder.addDefaultCase`");
        }
      }
      actionMatchers.push({
        matcher,
        reducer
      });
      return builder;
    },
    addDefaultCase(reducer) {
      if (process.env.NODE_ENV !== "production") {
        if (defaultCaseReducer) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(31) : "`builder.addDefaultCase` can only be called once");
        }
      }
      defaultCaseReducer = reducer;
      return builder;
    }
  };
  builderCallback(builder);
  return [actionsMap, actionMatchers, defaultCaseReducer];
}

// src/createReducer.ts
function isStateFunction(x) {
  return typeof x === "function";
}
function createReducer(initialState, mapOrBuilderCallback) {
  if (process.env.NODE_ENV !== "production") {
    if (typeof mapOrBuilderCallback === "object") {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(8) : "The object notation for `createReducer` has been removed. Please use the 'builder callback' notation instead: https://redux-toolkit.js.org/api/createReducer");
    }
  }
  let [actionsMap, finalActionMatchers, finalDefaultCaseReducer] = executeReducerBuilderCallback(mapOrBuilderCallback);
  let getInitialState;
  if (isStateFunction(initialState)) {
    getInitialState = () => freezeDraftable(initialState());
  } else {
    const frozenInitialState = freezeDraftable(initialState);
    getInitialState = () => frozenInitialState;
  }
  function reducer(state = getInitialState(), action) {
    let caseReducers = [actionsMap[action.type], ...finalActionMatchers.filter(({
      matcher
    }) => matcher(action)).map(({
      reducer: reducer2
    }) => reducer2)];
    if (caseReducers.filter((cr) => !!cr).length === 0) {
      caseReducers = [finalDefaultCaseReducer];
    }
    return caseReducers.reduce((previousState, caseReducer) => {
      if (caseReducer) {
        if (isDraft(previousState)) {
          const draft = previousState;
          const result = caseReducer(draft, action);
          if (result === void 0) {
            return previousState;
          }
          return result;
        } else if (!isDraftable(previousState)) {
          const result = caseReducer(previousState, action);
          if (result === void 0) {
            if (previousState === null) {
              return previousState;
            }
            throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(9) : "A case reducer on a non-draftable value must not return undefined");
          }
          return result;
        } else {
          return produce(previousState, (draft) => {
            return caseReducer(draft, action);
          });
        }
      }
      return previousState;
    }, state);
  }
  reducer.getInitialState = getInitialState;
  return reducer;
}

// src/createSlice.ts
var asyncThunkSymbol = /* @__PURE__ */ Symbol.for("rtk-slice-createasyncthunk");
function getType(slice, actionKey) {
  return `${slice}/${actionKey}`;
}
function buildCreateSlice({
  creators
} = {}) {
  const cAT = creators?.asyncThunk?.[asyncThunkSymbol];
  return function createSlice2(options) {
    const {
      name,
      reducerPath = name
    } = options;
    if (!name) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(11) : "`name` is a required option for createSlice");
    }
    if (typeof process !== "undefined" && process.env.NODE_ENV === "development") {
      if (options.initialState === void 0) {
        console.error("You must provide an `initialState` value that is not `undefined`. You may have misspelled `initialState`");
      }
    }
    const reducers = (typeof options.reducers === "function" ? options.reducers(buildReducerCreators()) : options.reducers) || {};
    const reducerNames = Object.keys(reducers);
    const context = {
      sliceCaseReducersByName: {},
      sliceCaseReducersByType: {},
      actionCreators: {},
      sliceMatchers: []
    };
    const contextMethods = {
      addCase(typeOrActionCreator, reducer2) {
        const type = typeof typeOrActionCreator === "string" ? typeOrActionCreator : typeOrActionCreator.type;
        if (!type) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(12) : "`context.addCase` cannot be called with an empty action type");
        }
        if (type in context.sliceCaseReducersByType) {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(13) : "`context.addCase` cannot be called with two reducers for the same action type: " + type);
        }
        context.sliceCaseReducersByType[type] = reducer2;
        return contextMethods;
      },
      addMatcher(matcher, reducer2) {
        context.sliceMatchers.push({
          matcher,
          reducer: reducer2
        });
        return contextMethods;
      },
      exposeAction(name2, actionCreator) {
        context.actionCreators[name2] = actionCreator;
        return contextMethods;
      },
      exposeCaseReducer(name2, reducer2) {
        context.sliceCaseReducersByName[name2] = reducer2;
        return contextMethods;
      }
    };
    reducerNames.forEach((reducerName) => {
      const reducerDefinition = reducers[reducerName];
      const reducerDetails = {
        reducerName,
        type: getType(name, reducerName),
        createNotation: typeof options.reducers === "function"
      };
      if (isAsyncThunkSliceReducerDefinition(reducerDefinition)) {
        handleThunkCaseReducerDefinition(reducerDetails, reducerDefinition, contextMethods, cAT);
      } else {
        handleNormalReducerDefinition(reducerDetails, reducerDefinition, contextMethods);
      }
    });
    function buildReducer() {
      if (process.env.NODE_ENV !== "production") {
        if (typeof options.extraReducers === "object") {
          throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(14) : "The object notation for `createSlice.extraReducers` has been removed. Please use the 'builder callback' notation instead: https://redux-toolkit.js.org/api/createSlice");
        }
      }
      const [extraReducers = {}, actionMatchers = [], defaultCaseReducer = void 0] = typeof options.extraReducers === "function" ? executeReducerBuilderCallback(options.extraReducers) : [options.extraReducers];
      const finalCaseReducers = {
        ...extraReducers,
        ...context.sliceCaseReducersByType
      };
      return createReducer(options.initialState, (builder) => {
        for (let key in finalCaseReducers) {
          builder.addCase(key, finalCaseReducers[key]);
        }
        for (let sM of context.sliceMatchers) {
          builder.addMatcher(sM.matcher, sM.reducer);
        }
        for (let m of actionMatchers) {
          builder.addMatcher(m.matcher, m.reducer);
        }
        if (defaultCaseReducer) {
          builder.addDefaultCase(defaultCaseReducer);
        }
      });
    }
    const selectSelf = (state) => state;
    const injectedSelectorCache = /* @__PURE__ */ new Map();
    let _reducer;
    function reducer(state, action) {
      if (!_reducer) _reducer = buildReducer();
      return _reducer(state, action);
    }
    function getInitialState() {
      if (!_reducer) _reducer = buildReducer();
      return _reducer.getInitialState();
    }
    function makeSelectorProps(reducerPath2, injected = false) {
      function selectSlice(state) {
        let sliceState = state[reducerPath2];
        if (typeof sliceState === "undefined") {
          if (injected) {
            sliceState = getInitialState();
          } else if (process.env.NODE_ENV !== "production") {
            throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(15) : "selectSlice returned undefined for an uninjected slice reducer");
          }
        }
        return sliceState;
      }
      function getSelectors(selectState = selectSelf) {
        const selectorCache = emplace(injectedSelectorCache, injected, {
          insert: () => /* @__PURE__ */ new WeakMap()
        });
        return emplace(selectorCache, selectState, {
          insert: () => {
            const map = {};
            for (const [name2, selector] of Object.entries(options.selectors ?? {})) {
              map[name2] = wrapSelector(selector, selectState, getInitialState, injected);
            }
            return map;
          }
        });
      }
      return {
        reducerPath: reducerPath2,
        getSelectors,
        get selectors() {
          return getSelectors(selectSlice);
        },
        selectSlice
      };
    }
    const slice = {
      name,
      reducer,
      actions: context.actionCreators,
      caseReducers: context.sliceCaseReducersByName,
      getInitialState,
      ...makeSelectorProps(reducerPath),
      injectInto(injectable, {
        reducerPath: pathOpt,
        ...config
      } = {}) {
        const newReducerPath = pathOpt ?? reducerPath;
        injectable.inject({
          reducerPath: newReducerPath,
          reducer
        }, config);
        return {
          ...slice,
          ...makeSelectorProps(newReducerPath, true)
        };
      }
    };
    return slice;
  };
}
function wrapSelector(selector, selectState, getInitialState, injected) {
  function wrapper(rootState, ...args) {
    let sliceState = selectState(rootState);
    if (typeof sliceState === "undefined") {
      if (injected) {
        sliceState = getInitialState();
      } else if (process.env.NODE_ENV !== "production") {
        throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(16) : "selectState returned undefined for an uninjected slice reducer");
      }
    }
    return selector(sliceState, ...args);
  }
  wrapper.unwrapped = selector;
  return wrapper;
}
var createSlice = /* @__PURE__ */ buildCreateSlice();
function buildReducerCreators() {
  function asyncThunk(payloadCreator, config) {
    return {
      _reducerDefinitionType: "asyncThunk" /* asyncThunk */,
      payloadCreator,
      ...config
    };
  }
  asyncThunk.withTypes = () => asyncThunk;
  return {
    reducer(caseReducer) {
      return Object.assign({
        // hack so the wrapping function has the same name as the original
        // we need to create a wrapper so the `reducerDefinitionType` is not assigned to the original
        [caseReducer.name](...args) {
          return caseReducer(...args);
        }
      }[caseReducer.name], {
        _reducerDefinitionType: "reducer" /* reducer */
      });
    },
    preparedReducer(prepare, reducer) {
      return {
        _reducerDefinitionType: "reducerWithPrepare" /* reducerWithPrepare */,
        prepare,
        reducer
      };
    },
    asyncThunk
  };
}
function handleNormalReducerDefinition({
  type,
  reducerName,
  createNotation
}, maybeReducerWithPrepare, context) {
  let caseReducer;
  let prepareCallback;
  if ("reducer" in maybeReducerWithPrepare) {
    if (createNotation && !isCaseReducerWithPrepareDefinition(maybeReducerWithPrepare)) {
      throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(17) : "Please use the `create.preparedReducer` notation for prepared action creators with the `create` notation.");
    }
    caseReducer = maybeReducerWithPrepare.reducer;
    prepareCallback = maybeReducerWithPrepare.prepare;
  } else {
    caseReducer = maybeReducerWithPrepare;
  }
  context.addCase(type, caseReducer).exposeCaseReducer(reducerName, caseReducer).exposeAction(reducerName, prepareCallback ? createAction(type, prepareCallback) : createAction(type));
}
function isAsyncThunkSliceReducerDefinition(reducerDefinition) {
  return reducerDefinition._reducerDefinitionType === "asyncThunk" /* asyncThunk */;
}
function isCaseReducerWithPrepareDefinition(reducerDefinition) {
  return reducerDefinition._reducerDefinitionType === "reducerWithPrepare" /* reducerWithPrepare */;
}
function handleThunkCaseReducerDefinition({
  type,
  reducerName
}, reducerDefinition, context, cAT) {
  if (!cAT) {
    throw new Error(process.env.NODE_ENV === "production" ? formatProdErrorMessage(18) : "Cannot use `create.asyncThunk` in the built-in `createSlice`. Use `buildCreateSlice({ creators: { asyncThunk: asyncThunkCreator } })` to create a customised version of `createSlice`.");
  }
  const {
    payloadCreator,
    fulfilled,
    pending,
    rejected,
    settled,
    options
  } = reducerDefinition;
  const thunk = cAT(type, payloadCreator, options);
  context.exposeAction(reducerName, thunk);
  if (fulfilled) {
    context.addCase(thunk.fulfilled, fulfilled);
  }
  if (pending) {
    context.addCase(thunk.pending, pending);
  }
  if (rejected) {
    context.addCase(thunk.rejected, rejected);
  }
  if (settled) {
    context.addMatcher(thunk.settled, settled);
  }
  context.exposeCaseReducer(reducerName, {
    fulfilled: fulfilled || noop,
    pending: pending || noop,
    rejected: rejected || noop,
    settled: settled || noop
  });
}
function noop() {
}

// src/formatProdErrorMessage.ts
function formatProdErrorMessage(code) {
  return `Minified Redux Toolkit error #${code}; visit https://redux-toolkit.js.org/Errors?code=${code} for the full message or use the non-minified dev environment for full errors. `;
}

const initialState$5 = {
    peerId: "",
    publicKey: "",
    secretKey: "",
};
const keyPairSlice = createSlice({
    name: "keyPair",
    initialState: initialState$5,
    reducers: {
        setKeyPair: (state, action) => {
            return {
                ...state,
                publicKey: action.payload.publicKey,
                secretKey: action.payload.secretKey,
            };
        },
        setPeerId: (state, action) => {
            if (!isUUID(action.payload.peerId, 4))
                return state;
            return {
                ...state,
                peerId: action.payload.peerId,
            };
        },
    },
});
const { setKeyPair, setPeerId } = keyPairSlice.actions;
const keyPairSelector = (state) => state.keyPair;
var keyPairReducer = keyPairSlice.reducer;

const initialState$4 = [];
const roomsSlice = createSlice({
    name: "rooms",
    initialState: initialState$4,
    reducers: {
        setRoomUrl: (state, action) => {
            const url = action.payload;
            const roomIndex = state.findIndex((r) => r.url === url);
            if (roomIndex > -1)
                return state;
            state.push({ url });
            return state;
        },
        setRoom: (state, action) => {
            const { url, id } = action.payload;
            if (!isUUID(id))
                return state;
            const roomIndex = state.findIndex((r) => r.url === url);
            if (roomIndex !== -1) {
                if (state[roomIndex].id !== id) {
                    state.splice(roomIndex, 1, Object.assign(state[roomIndex], {
                        id,
                    }));
                }
                else {
                    return state;
                }
            }
            else {
                state.push(action.payload);
            }
            return state;
        },
    },
});
const { setRoom, setRoomUrl } = roomsSlice.actions;
const roomsSelector = (state) => state.rooms;
var roomsReducer = roomsSlice.reducer;

const initialState$3 = false;
const isSettingRemoteAnswerPendingSlice = createSlice({
    name: "isSettingRemoteAnswerPending",
    initialState: initialState$3,
    reducers: {
        setIsSettingRemoteAnswerPending: (_state, action) => {
            return action.payload;
        },
    },
});
const { setIsSettingRemoteAnswerPending } = isSettingRemoteAnswerPendingSlice.actions;
var isSettingRemoteAnswerPendingReducer = isSettingRemoteAnswerPendingSlice.reducer;

const initialState$2 = [];
const peersSlice = createSlice({
    name: "peers",
    initialState: initialState$2,
    reducers: {
        setPeer: (state, action) => {
            const { peerId, peerPublicKey } = action.payload;
            // if (epc.withPeerId === peerId) return state;
            const peerIndex = state.findIndex((peer) => {
                peer.id === peerId;
            });
            if (peerIndex === -1) {
                const lastPeerIndex = state.length;
                state.push({
                    connectionIndex: lastPeerIndex,
                    id: peerId,
                    publicKey: peerPublicKey,
                });
            }
            else {
                state[peerIndex] = {
                    ...state[peerIndex],
                    publicKey: peerPublicKey,
                };
            }
            return state;
        },
        setDescription: (state, _action) => {
            return state;
        },
        setCandidate: (state, _action) => {
            return state;
        },
        setPeerChannel: (state, _action) => {
            return state;
        },
        deletePeer: (state, action) => {
            const { peerId } = action.payload;
            const peerIndex = state.findIndex((peer) => peer.id === peerId);
            if (peerIndex > -1) {
                state.splice(peerIndex, 1);
            }
            return state;
        },
        deleteAllPeers: (_state) => {
            return [];
        },
    },
});
const { setPeer, setDescription, setCandidate, setPeerChannel, deletePeer, deleteAllPeers, } = peersSlice.actions;
const peersSelector = (state) => state.peers;
var peers2Reducer = peersSlice.reducer;

const initialState$1 = [];
const channelsSlice = createSlice({
    name: "channels",
    initialState: initialState$1,
    reducers: {
        setChannel: (state, action) => {
            const { label, roomId, epc } = action.payload;
            const channelIndex = state.findIndex((c) => c.withPeerId === epc.withPeerId && c.label === label);
            if (channelIndex === -1) {
                state.push({
                    // extChannel
                    roomId,
                    label,
                    withPeerId: epc.withPeerId,
                    messages: [],
                });
            }
            else {
                state.splice(channelIndex, 1, Object.assign(state[channelIndex], {
                    roomId,
                    label,
                    withPeerId: epc.withPeerId,
                }));
            }
            return state;
        },
        setMessage: (state, action) => {
            const { message, fromPeerId, toPeerId, channel } = action.payload;
            const channelIndex = state.findIndex((c) => c.label === channel &&
                (c.withPeerId === fromPeerId || c.withPeerId === toPeerId));
            if (channelIndex === -1)
                return state;
            const messageIndex = state[channelIndex].messages.findIndex((msg) => msg.message === message &&
                msg.fromPeerId === fromPeerId &&
                msg.toPeerId === toPeerId);
            const newMessage = messageIndex === -1
                ? {
                    id: window.crypto.randomUUID(),
                    fromPeerId,
                    toPeerId,
                    timestamp: new Date(),
                    message,
                }
                : Object.assign(state[channelIndex].messages[messageIndex], {
                    timestamp: new Date(),
                });
            if (messageIndex === -1) {
                state[channelIndex].messages.push(newMessage);
            }
            else {
                state[channelIndex].messages[messageIndex] = Object.assign(state[channelIndex].messages[messageIndex], newMessage);
            }
            return state;
        },
        sendMessageToChannel: (state, action) => {
            const { message, fromPeerId, channel } = action.payload;
            let channelIndex = state.findIndex((c) => c.label === channel);
            if (channelIndex === -1)
                return state;
            while (channelIndex > -1) {
                state[channelIndex].messages.push({
                    id: window.crypto.randomUUID(),
                    fromPeerId: fromPeerId,
                    toPeerId: state[channelIndex].withPeerId,
                    timestamp: new Date(),
                    message,
                });
                channelIndex = state.findIndex((c) => {
                    c.label === channel;
                });
            }
            return state;
        },
        deletePeerChannels: (state, action) => {
            const { peerId } = action.payload;
            const CHANNELS_LEN = state.length;
            const channelsClosedIndexes = [];
            for (let i = 0; i < CHANNELS_LEN; i++) {
                if (state[i].withPeerId !== peerId)
                    continue;
                channelsClosedIndexes.push(i);
            }
            const INDEXES_LEN = channelsClosedIndexes.length;
            for (let i = 0; i < INDEXES_LEN; i++) {
                state.splice(channelsClosedIndexes[i], 1);
            }
            return state;
        },
        deleteLabelChannels: (state, action) => {
            const { channel } = action.payload;
            const CHANNELS_LEN = state.length;
            const channelsClosedIndexes = [];
            for (let i = 0; i < CHANNELS_LEN; i++) {
                if (state[i].label !== channel)
                    continue;
                channelsClosedIndexes.push(i);
            }
            const INDEXES_LEN = channelsClosedIndexes.length;
            for (let i = 0; i < INDEXES_LEN; i++) {
                state.splice(channelsClosedIndexes[i], 1);
            }
            return state;
        },
        deleteChannel: (state, action) => {
            const { channel, peerId } = action.payload;
            const channelIndex = state.findIndex((c) => c.label === channel && c.withPeerId === peerId);
            if (channelIndex > -1) {
                state.splice(channelIndex, 1);
            }
            return state;
        },
        deleteAllChannels: (_state) => {
            return [];
        },
        deleteMessage: (state, action) => {
            const { channel, peerId, messageId } = action.payload;
            const channelIndex = state.findIndex((c) => c.label === channel && c.withPeerId === peerId);
            const messageIndex = state[channelIndex].messages.findIndex((msg) => msg.id === messageId);
            if (messageIndex > -1) {
                state[channelIndex].messages.splice(messageIndex, 1);
            }
            return state;
        },
        deleteChannelMessages: (state, action) => {
            const { channel } = action.payload;
            const channelIndex = state.findIndex((c) => c.label === channel);
            if (channelIndex > -1) {
                state[channelIndex].messages = [];
            }
            return state;
        },
        deletePeerMessages: (state, action) => {
            const { peerId } = action.payload;
            let channelIndex = state.findIndex((c) => {
                c.withPeerId === peerId;
            });
            while (channelIndex > -1) {
                state.splice(channelIndex, 1);
                channelIndex = state.findIndex((c) => {
                    c.withPeerId === peerId;
                });
            }
            return state;
        },
        deleteAllMessages: () => {
            return [];
        },
    },
});
const { setChannel, setMessage, sendMessageToChannel, deleteChannel, deletePeerChannels, deleteLabelChannels, deleteAllChannels, } = channelsSlice.actions;
const channelsSelector = (state) => state.channels;
var channels2Reducer = channelsSlice.reducer;

const initialState = {
    isEstablishingConnection: false,
    isConnected: false,
    serverUrl: "ws://localhost:3001/ws",
};
const signalingServerSlice = createSlice({
    name: "signalingServer",
    initialState,
    reducers: {
        startConnecting: (state, action) => {
            state.isEstablishingConnection = true;
            state.serverUrl = action.payload ?? "ws://localhost:3001/ws";
        },
        connectionEstablished: (state) => {
            state.isConnected = true;
            state.isEstablishingConnection = true;
        },
        disconnect: (state) => {
            state.isConnected = false;
            state.isEstablishingConnection = false;
        },
        sendMessage: (state, _action) => {
            return state;
        },
        // receiveMessage: (
        //   state,
        //   action: PayloadAction<{
        //     message: PeerId | Description | Candidate;
        //   }>,
        // ) => {
        //   state.messages.push(action.payload.message);
        // },
    },
});
const signalingServerActions = signalingServerSlice.actions;
const signalingServerSelector = (state) => state.signalingServer;
var signalingServerReducer = signalingServerSlice.reducer;

const E_CANCELED = new Error('request for lock canceled');

var __awaiter$2 = function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
class Semaphore {
    constructor(_value, _cancelError = E_CANCELED) {
        this._value = _value;
        this._cancelError = _cancelError;
        this._queue = [];
        this._weightedWaiters = [];
    }
    acquire(weight = 1, priority = 0) {
        if (weight <= 0)
            throw new Error(`invalid weight ${weight}: must be positive`);
        return new Promise((resolve, reject) => {
            const task = { resolve, reject, weight, priority };
            const i = findIndexFromEnd(this._queue, (other) => priority <= other.priority);
            if (i === -1 && weight <= this._value) {
                // Needs immediate dispatch, skip the queue
                this._dispatchItem(task);
            }
            else {
                this._queue.splice(i + 1, 0, task);
            }
        });
    }
    runExclusive(callback_1) {
        return __awaiter$2(this, arguments, void 0, function* (callback, weight = 1, priority = 0) {
            const [value, release] = yield this.acquire(weight, priority);
            try {
                return yield callback(value);
            }
            finally {
                release();
            }
        });
    }
    waitForUnlock(weight = 1, priority = 0) {
        if (weight <= 0)
            throw new Error(`invalid weight ${weight}: must be positive`);
        if (this._couldLockImmediately(weight, priority)) {
            return Promise.resolve();
        }
        else {
            return new Promise((resolve) => {
                if (!this._weightedWaiters[weight - 1])
                    this._weightedWaiters[weight - 1] = [];
                insertSorted(this._weightedWaiters[weight - 1], { resolve, priority });
            });
        }
    }
    isLocked() {
        return this._value <= 0;
    }
    getValue() {
        return this._value;
    }
    setValue(value) {
        this._value = value;
        this._dispatchQueue();
    }
    release(weight = 1) {
        if (weight <= 0)
            throw new Error(`invalid weight ${weight}: must be positive`);
        this._value += weight;
        this._dispatchQueue();
    }
    cancel() {
        this._queue.forEach((entry) => entry.reject(this._cancelError));
        this._queue = [];
    }
    _dispatchQueue() {
        this._drainUnlockWaiters();
        while (this._queue.length > 0 && this._queue[0].weight <= this._value) {
            this._dispatchItem(this._queue.shift());
            this._drainUnlockWaiters();
        }
    }
    _dispatchItem(item) {
        const previousValue = this._value;
        this._value -= item.weight;
        item.resolve([previousValue, this._newReleaser(item.weight)]);
    }
    _newReleaser(weight) {
        let called = false;
        return () => {
            if (called)
                return;
            called = true;
            this.release(weight);
        };
    }
    _drainUnlockWaiters() {
        if (this._queue.length === 0) {
            for (let weight = this._value; weight > 0; weight--) {
                const waiters = this._weightedWaiters[weight - 1];
                if (!waiters)
                    continue;
                waiters.forEach((waiter) => waiter.resolve());
                this._weightedWaiters[weight - 1] = [];
            }
        }
        else {
            const queuedPriority = this._queue[0].priority;
            for (let weight = this._value; weight > 0; weight--) {
                const waiters = this._weightedWaiters[weight - 1];
                if (!waiters)
                    continue;
                const i = waiters.findIndex((waiter) => waiter.priority <= queuedPriority);
                (i === -1 ? waiters : waiters.splice(0, i))
                    .forEach((waiter => waiter.resolve()));
            }
        }
    }
    _couldLockImmediately(weight, priority) {
        return (this._queue.length === 0 || this._queue[0].priority < priority) &&
            weight <= this._value;
    }
}
function insertSorted(a, v) {
    const i = findIndexFromEnd(a, (other) => v.priority <= other.priority);
    a.splice(i + 1, 0, v);
}
function findIndexFromEnd(a, predicate) {
    for (let i = a.length - 1; i >= 0; i--) {
        if (predicate(a[i])) {
            return i;
        }
    }
    return -1;
}

var __awaiter$1 = function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
class Mutex {
    constructor(cancelError) {
        this._semaphore = new Semaphore(1, cancelError);
    }
    acquire() {
        return __awaiter$1(this, arguments, void 0, function* (priority = 0) {
            const [, releaser] = yield this._semaphore.acquire(1, priority);
            return releaser;
        });
    }
    runExclusive(callback, priority = 0) {
        return this._semaphore.runExclusive(() => callback(), 1, priority);
    }
    isLocked() {
        return this._semaphore.isLocked();
    }
    waitForUnlock(priority = 0) {
        return this._semaphore.waitForUnlock(1, priority);
    }
    release() {
        if (this._semaphore.isLocked())
            this._semaphore.release();
    }
    cancel() {
        return this._semaphore.cancel();
    }
}

const exportPublicKey = async (keys) => {
    const exported = await window.crypto.subtle.exportKey("spki", keys.publicKey);
    const exportedAsBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exported)));
    const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
    return pemExported;
};
const exportPrivateKey = async (keys) => {
    const exported = await window.crypto.subtle.exportKey("pkcs8", keys.privateKey);
    const exportedAsBase64 = window.btoa(String.fromCharCode(...new Uint8Array(exported)));
    const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
    return pemExported;
};
const exportPublicKeyToHex = async (publicKey) => {
    const spki = await window.crypto.subtle.exportKey("spki", publicKey);
    const result = [...new Uint8Array(spki)]
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("");
    return "0x" + result.toLowerCase();
};
const exportPemKeys = async (keys) => {
    try {
        const publicKey = await exportPublicKey(keys);
        const secretKey = await exportPrivateKey(keys);
        return { publicKey, secretKey };
    }
    catch (error) {
        throw error;
    }
};

const str2ab = (str) => {
    const buf = new ArrayBuffer(str.length);
    const bufView = new Uint8Array(buf);
    for (let i = 0, strLen = str.length; i < strLen; i++) {
        bufView[i] = str.charCodeAt(i);
    }
    return buf;
};
const importPrivateKey = async (pemKey) => {
    try {
        const pemHeader = "-----BEGIN PRIVATE KEY-----";
        const pemFooter = "-----END PRIVATE KEY-----";
        const pemContents = pemKey.substring(pemHeader.length, pemKey.length - pemFooter.length);
        // base64 decode the string to get the binary data
        const binaryDerString = window.atob(pemContents);
        // convert from a binary string to an ArrayBuffer
        const binaryDer = str2ab(binaryDerString);
        return await window.crypto.subtle.importKey("pkcs8", binaryDer, {
            name: "RSA-PSS",
            hash: "SHA-256",
        }, true, ["sign"]);
    }
    catch (error) {
        throw error;
    }
};
const importPublicKey = async (pemKey) => {
    try {
        const pemHeader = "-----BEGIN PUBLIC KEY-----";
        const pemFooter = "-----END PUBLIC KEY-----";
        const pemContents = pemKey.substring(pemHeader.length, pemKey.length - pemFooter.length);
        // base64 decode the string to get the binary data
        const binaryDerString = window.atob(pemContents);
        // convert from a binary string to an ArrayBuffer
        const binaryDer = str2ab(binaryDerString);
        return await window.crypto.subtle.importKey("spki", binaryDer, {
            name: "RSA-PSS",
            hash: "SHA-256",
        }, true, ["verify"]);
    }
    catch (error) {
        throw error;
    }
};

// Mutex to control WebSocket connection (optional)
const socketMutex = new Mutex();
const signalingServerMiddleware = (store) => {
    let ws;
    return (next) => async (action) => {
        const { signalingServer } = store.getState();
        const isConnectionEstablished = ws != undefined &&
            ws.readyState !== WebSocket.CLOSED &&
            ws.readyState !== WebSocket.CLOSING &&
            signalingServer.isConnected;
        if (signalingServerActions.startConnecting.match(action) &&
            !isConnectionEstablished) {
            const { keyPair } = store.getState();
            await socketMutex.runExclusive(async () => {
                let publicKey = "";
                if (!isConnectionEstablished && keyPair.secretKey.length === 0) {
                    const newKeyPair = await crypto.subtle.generateKey({
                        name: "RSA-PSS",
                        hash: "SHA-256",
                        modulusLength: 4096,
                        publicExponent: new Uint8Array([1, 0, 1]),
                    }, true, ["sign", "verify"]);
                    const pair = await exportPemKeys(newKeyPair);
                    store.dispatch(setKeyPair(pair));
                    publicKey = await exportPublicKeyToHex(newKeyPair.publicKey);
                }
                else if (!isConnectionEstablished) {
                    const publicKeyPem = await importPublicKey(keyPair.publicKey);
                    publicKey = await exportPublicKeyToHex(publicKeyPem);
                }
                ws = new WebSocket(signalingServer.serverUrl + "?publickey=" + publicKey);
                ws.onopen = () => {
                    console.log("WebSocket connected");
                    store.dispatch(signalingServerActions.connectionEstablished());
                };
                ws.onerror = (error) => {
                    console.error("WebSocket error:", error);
                    ws.removeEventListener("message", () => { });
                    ws.removeEventListener("open", () => { });
                    ws.removeEventListener("close", () => { });
                    ws.close();
                };
                ws.onclose = () => {
                    console.log("WebSocket closed");
                };
                ws.onmessage = async (event) => {
                    console.log("Message from server:", JSON.parse(event.data));
                    if (event.data === "PING")
                        return ws.send("PONG");
                    const message = JSON.parse(event.data);
                    switch (message.type) {
                        case "peerId": {
                            const { keyPair } = store.getState();
                            const peerId = message.peerId ?? "";
                            const challenge = message.challenge ?? "";
                            store.dispatch(setPeerId({
                                peerId,
                            }));
                            try {
                                const secretKey = await importPrivateKey(keyPair.secretKey);
                                const nonce = Uint8Array.from(challenge
                                    .match(/.{1,2}/g)
                                    .map((byte) => parseInt(byte, 16)));
                                const signature = await window.crypto.subtle.sign({
                                    name: "RSA-PSS",
                                    saltLength: 32,
                                }, secretKey, nonce);
                                store.dispatch(signalingServerActions.sendMessage({
                                    content: {
                                        type: "challenge",
                                        fromPeerId: peerId,
                                        challenge,
                                        signature: "0x" +
                                            [...new Uint8Array(signature)]
                                                .map((x) => x.toString(16).padStart(2, "0"))
                                                .join(""),
                                    },
                                }));
                                // ws.send(
                                //   JSON.stringify({
                                //     type: "challenge",
                                //     fromPeerId: peerId,
                                //     challenge,
                                //     signature:
                                //       "0x" +
                                //       [...new Uint8Array(signature)]
                                //         .map((x) => x.toString(16).padStart(2, "0"))
                                //         .join(""),
                                //   }),
                                // );
                            }
                            catch (error) {
                                throw error;
                            }
                            break;
                        }
                        case "roomId": {
                            store.dispatch(setRoom({
                                id: message.roomId,
                                url: message.roomUrl,
                            }));
                            break;
                        }
                        case "description": {
                            store.dispatch(setDescription({
                                peerId: message.fromPeerId,
                                roomId: message.roomId,
                                description: message.description,
                            }));
                            break;
                        }
                        case "candidate": {
                            store.dispatch(setCandidate({
                                peerId: message.fromPeerId,
                                roomId: message.roomId,
                                candidate: message.candidate,
                            }));
                            break;
                        }
                        default: {
                            console.error("Unknown message type");
                            break;
                        }
                    }
                };
            });
            return next(action);
        }
        if (signalingServerActions.disconnect.match(action) &&
            isConnectionEstablished) {
            ws.removeEventListener("message", () => { });
            ws.removeEventListener("open", () => { });
            ws.removeEventListener("close", () => { });
            ws.close();
            return next(action);
        }
        if (signalingServerActions.sendMessage.match(action) &&
            isConnectionEstablished) {
            ws.send(JSON.stringify(action.payload.content));
            console.log(JSON.stringify(action.payload.content));
            return next(action);
        }
        return next(action);
    };
};

const channelsMiddleware = (store) => {
    const dataChannels = [];
    const openDataChannel = async (channel, epc) => {
        const label = typeof channel === "string" ? channel : channel.label;
        const dataChannel = typeof channel === "string" ? epc.createDataChannel(channel) : channel;
        const extChannel = dataChannel;
        extChannel.withPeerId = epc.withPeerId;
        extChannel.onopen = () => {
            console.log(`Channel with label \"${extChannel.label}\" and client ${epc.withPeerId} is open.`);
            const message = `Connected with ${epc.withPeerId} on channel ${extChannel.label}`;
            extChannel.send(message);
            const { keyPair } = store.getState();
            store.dispatch(setMessage({
                message,
                fromPeerId: keyPair.peerId,
                toPeerId: extChannel.withPeerId,
                channel: label,
            }));
        };
        extChannel.onclosing = () => {
            console.log(`Channel with label ${channel} is closing.`);
        };
        extChannel.onclose = async () => {
            console.log(`Channel with label ${channel} has closed.`);
            store.dispatch(deleteChannel({
                channel: label,
                peerId: epc.withPeerId,
            }));
            if (channel === "signaling") {
                store.dispatch(deletePeerChannels({ peerId: epc.withPeerId }));
                store.dispatch(deletePeer({ peerId: epc.withPeerId }));
            }
        };
        extChannel.onerror = async (e) => {
            console.error(e);
            store.dispatch(deleteChannel({
                channel: label,
                peerId: epc.withPeerId,
            }));
        };
        extChannel.onmessage = (e) => {
            if (typeof e.data === "string" && e.data.length > 0) {
                const { keyPair } = store.getState();
                store.dispatch(setMessage({
                    message: e.data,
                    fromPeerId: epc.withPeerId,
                    toPeerId: keyPair.peerId,
                    channel: extChannel.label,
                }));
            }
        };
        return extChannel;
    };
    return (next) => async (action) => {
        if (deleteChannel.match(action)) {
            const { peerId, channel } = action.payload;
            const channelIndex = dataChannels.findIndex((c) => c.label === channel && c.withPeerId === peerId);
            if (channelIndex > -1) {
                if (dataChannels[channelIndex].readyState === "open") {
                    dataChannels[channelIndex].onopen = null;
                    dataChannels[channelIndex].onclose = null;
                    dataChannels[channelIndex].onerror = null;
                    dataChannels[channelIndex].onclosing = null;
                    dataChannels[channelIndex].onmessage = null;
                    dataChannels[channelIndex].onbufferedamountlow = null;
                    dataChannels[channelIndex].close();
                }
                dataChannels.splice(channelIndex, 1);
            }
            return next(action);
        }
        if (deleteAllChannels.match(action)) {
            const CHANNELS_LEN = dataChannels.length;
            for (let i = 0; i < CHANNELS_LEN; i++) {
                if (dataChannels[i].readyState === "open") {
                    dataChannels[i].onopen = null;
                    dataChannels[i].onclose = null;
                    dataChannels[i].onerror = null;
                    dataChannels[i].onclosing = null;
                    dataChannels[i].onmessage = null;
                    dataChannels[i].onbufferedamountlow = null;
                    dataChannels[i].close();
                }
                dataChannels.splice(i, 1);
            }
            return next(action);
        }
        if (deletePeerChannels.match(action)) {
            const { peerId } = action.payload;
            const CHANNELS_LEN = dataChannels.length;
            const channelsClosedIndexes = [];
            for (let i = 0; i < CHANNELS_LEN; i++) {
                if (dataChannels[i].withPeerId !== peerId)
                    continue;
                dataChannels[i].onopen = null;
                dataChannels[i].onclose = null;
                dataChannels[i].onerror = null;
                dataChannels[i].onclosing = null;
                dataChannels[i].onmessage = null;
                dataChannels[i].onbufferedamountlow = null;
                dataChannels[i].close();
                channelsClosedIndexes.push(i);
            }
            const INDEXES_LEN = channelsClosedIndexes.length;
            for (let i = 0; i < INDEXES_LEN; i++) {
                dataChannels.splice(channelsClosedIndexes[i], 1);
            }
            return next(action);
        }
        if (deleteLabelChannels.match(action)) {
            const { channel } = action.payload;
            const CHANNELS_LEN = dataChannels.length;
            const channelsClosedIndexes = [];
            for (let i = 0; i < CHANNELS_LEN; i++) {
                if (dataChannels[i].label !== channel ||
                    dataChannels[i].readyState !== "open")
                    continue;
                dataChannels[i].onopen = null;
                dataChannels[i].onclose = null;
                dataChannels[i].onerror = null;
                dataChannels[i].onclosing = null;
                dataChannels[i].onmessage = null;
                dataChannels[i].onbufferedamountlow = null;
                dataChannels[i].close();
                channelsClosedIndexes.push(i);
            }
            const INDEXES_LEN = channelsClosedIndexes.length;
            for (let i = 0; i < INDEXES_LEN; i++) {
                dataChannels.splice(channelsClosedIndexes[i], 1);
            }
            return next(action);
        }
        if (setChannel.match(action)) {
            const { channel, label, epc } = action.payload;
            const channelIndex = dataChannels.findIndex((c) => {
                c.label === label && c.withPeerId === epc.withPeerId;
            });
            if (channelIndex > -1)
                return next(action);
            const dataChannel = await openDataChannel(channel, epc);
            dataChannels.push(dataChannel);
            return next(action);
        }
        if (setMessage.match(action)) {
            const { channel, toPeerId, message } = action.payload;
            const channelIndex = dataChannels.findIndex((c) => c.label === channel && c.withPeerId === toPeerId);
            if (channelIndex > -1) {
                dataChannels[channelIndex].send(message);
            }
            return next(action);
        }
        if (sendMessageToChannel.match(action)) {
            const { message, channel } = action.payload;
            let channelIndex = dataChannels.findIndex((c) => c.label === channel);
            if (channelIndex === -1)
                return next(action); // TODO open channel and send
            while (channelIndex > -1) {
                dataChannels[channelIndex].send(message);
                dataChannels.splice(channelIndex, 1);
                channelIndex = dataChannels.findIndex((c) => {
                    c.label === channel;
                });
            }
            return next(action);
        }
        return next(action);
    };
};

const getConnectedRoomPeers = async (roomUrl, httpServerUrl = "http://localhost:3001") => {
    if (roomUrl.length === 0)
        return [];
    const getRoomPeers = await fetch(`${httpServerUrl}/room/${roomUrl}/peers`, {
        method: "GET",
        headers: {
            Accept: "application/json",
            "Content-Type": "application/json",
        },
    });
    try {
        const c = await getRoomPeers.json();
        return c;
    }
    catch (e) {
        console.warn(e);
        return [];
    }
};

const peersMiddleware = (store) => {
    const peerConnections = [];
    const iceCandidates = [];
    const rtcConnectWithPeer = async (peerId, roomId, initiator = true, rtcConfig = {
        iceServers: [
            {
                urls: [
                    "stun:stun.l.google.com:19302",
                    "stun:stun1.l.google.com:19302",
                ],
            },
        ],
    }) => {
        const { keyPair } = store.getState();
        if (peerId === keyPair.peerId)
            throw new Error("Cannot create a connection with oneself.");
        const peerIndex = peerConnections.findIndex((peer) => peer.withPeerId === peerId);
        if (peerIndex !== -1)
            return peerConnections[peerIndex];
        if (initiator)
            console.log(`You have initiated a peer connection with ${peerId}.`);
        const pc = new RTCPeerConnection(rtcConfig);
        const epc = pc;
        epc.peerIsInitiator = initiator;
        epc.withPeerId = peerId;
        epc.makingOffer = false;
        epc.onnegotiationneeded = async () => {
            try {
                epc.makingOffer = true;
                await epc.setLocalDescription();
                const description = epc.localDescription;
                if (description) {
                    store.dispatch(signalingServerActions.sendMessage({
                        content: {
                            type: "description",
                            description,
                            fromPeerId: keyPair.peerId,
                            toPeerId: peerId,
                            roomId,
                        },
                    }));
                    console.log(`Negotiation was needed with ${peerId} and you sent a description ${description.type}.`);
                }
            }
            catch (err) {
                console.error(err);
            }
            finally {
                epc.makingOffer = false;
            }
        };
        epc.onicecandidate = ({ candidate }) => {
            if (candidate && candidate.candidate !== "") {
                store.dispatch(signalingServerActions.sendMessage({
                    content: {
                        type: "candidate",
                        candidate,
                        toPeerId: peerId,
                    },
                }));
                console.log(`ICE candidate was sent to ${peerId}.`);
            }
        };
        epc.onicecandidateerror = async () => {
            store.dispatch(deletePeer({ peerId: epc.withPeerId }));
            console.error(`ICE candidate error with ${peerId}`);
        };
        epc.oniceconnectionstatechange = async () => {
            console.log(`ICE candidate connection state with ${peerId} is ${epc.iceConnectionState}.`);
            if (epc.iceConnectionState === "failed") {
                epc.restartIce();
            }
        };
        epc.onicegatheringstatechange = async () => {
            console.log(`ICE gathering state with ${peerId} is ${epc.iceGatheringState}.`);
        };
        epc.onsignalingstatechange = async () => {
            console.log(`Signaling state with ${peerId} is ${epc.signalingState}.`);
            if (epc.signalingState === "stable" && initiator) {
                const CANDIDATES_LEN = iceCandidates.length;
                const indexes = [];
                for (let i = 0; i < CANDIDATES_LEN; i++) {
                    if (iceCandidates[i].withPeerId !== peerId)
                        continue;
                    try {
                        await epc.addIceCandidate(iceCandidates[i]);
                        indexes.push(i);
                    }
                    catch (error) {
                        throw error;
                    }
                }
                while (indexes.length > 0) {
                    iceCandidates.splice(indexes[0], 1);
                    indexes.splice(0, 1);
                }
            }
        };
        epc.onconnectionstatechange = async () => {
            if (epc.connectionState === "closed" ||
                epc.connectionState === "failed" ||
                epc.connectionState === "disconnected") {
                store.dispatch(deletePeer({ peerId }));
                console.error(`Connection with peer ${peerId} has ${epc.connectionState}.`);
            }
            else {
                console.log(`Connection status with peer ${peerId} is ${epc.connectionState}.`);
                if (epc.connectionState === "connected" && !epc.peerIsInitiator) {
                    await rtcConnectWithRoom(roomId, true, rtcConfig);
                }
            }
        };
        epc.ondatachannel = async (e) => {
            // await openDataChannel(e.channel, epc);
            store.dispatch(setChannel({
                label: e.channel.label,
                channel: e.channel,
                roomId,
                epc,
            }));
        };
        if (initiator) {
            store.dispatch(setChannel({
                label: "signaling",
                channel: "signaling",
                roomId,
                epc,
            }));
        } // await openDataChannel("signaling", epc);
        return epc;
    };
    const rtcConnectWithRoom = async (roomId, starConfig = false, rtcConfig = {
        iceServers: [
            {
                urls: [
                    "stun:stun.l.google.com:19302",
                    "stun:stun1.l.google.com:19302",
                ],
            },
        ],
    }) => {
        try {
            const clientsInRoom = await getConnectedRoomPeers(roomId);
            const ROOM_CLIENTS_LEN = clientsInRoom.length;
            const { keyPair } = store.getState();
            if (roomId.length > 0 &&
                keyPair.peerId.length > 0 &&
                ROOM_CLIENTS_LEN > peerConnections.length + 1) {
                for (let i = 0; i < ROOM_CLIENTS_LEN; i++) {
                    const withPeerId = clientsInRoom[i].id;
                    if (withPeerId === keyPair.peerId)
                        continue;
                    const peerIndex = peerConnections.findIndex((peer) => peer.withPeerId === withPeerId);
                    if (peerIndex !== -1)
                        continue;
                    if (!starConfig) {
                        const epc = await rtcConnectWithPeer(withPeerId, roomId, true, rtcConfig);
                        peerConnections.push(epc);
                    }
                    else {
                        const clientIndex = clientsInRoom.findIndex((client) => client.id === keyPair.peerId);
                        if (clientIndex === -1)
                            throw new Error("Impossible! Current client is not in the room");
                        if (clientsInRoom[clientIndex].createdAt > clientsInRoom[i].createdAt) {
                            // One of them needs to be an initiator and createdAt does not change
                            await rtcConnectWithPeer(withPeerId, roomId, true, rtcConfig);
                        }
                        else if (clientsInRoom[clientIndex].createdAt ===
                            clientsInRoom[i].createdAt) {
                            if (clientsInRoom[clientIndex].updatedAt >
                                clientsInRoom[i].updatedAt) {
                                const epc = await rtcConnectWithPeer(withPeerId, roomId, true, rtcConfig);
                                peerConnections.push(epc);
                            }
                            else {
                                continue;
                            }
                        }
                        else {
                            continue;
                        }
                    }
                }
            }
        }
        catch (error) {
            throw error;
        }
    };
    return (next) => async (action) => {
        const { isSettingRemoteAnswerPending } = store.getState();
        if (deletePeer.match(action)) {
            const { peerId } = action.payload;
            const peerIndex = peerConnections.findIndex((peer) => peer.withPeerId === peerId);
            if (peerIndex > -1 &&
                (peerConnections[peerIndex].connectionState === "connected" ||
                    peerConnections[peerIndex].connectionState === "failed")) {
                peerConnections[peerIndex].ontrack = null;
                peerConnections[peerIndex].ondatachannel = null;
                peerConnections[peerIndex].onicecandidate = null;
                peerConnections[peerIndex].onicecandidateerror = null;
                peerConnections[peerIndex].onnegotiationneeded = null;
                peerConnections[peerIndex].onsignalingstatechange = null;
                peerConnections[peerIndex].onconnectionstatechange = null;
                peerConnections[peerIndex].onicegatheringstatechange = null;
                peerConnections[peerIndex].oniceconnectionstatechange = null;
                peerConnections[peerIndex].close();
                peerConnections.splice(peerIndex, 1);
            }
            return next(action);
        }
        if (deleteAllPeers.match(action)) {
            const PEER_CONNECTIONS_LEN = peerConnections.length;
            for (let i = 0; i < PEER_CONNECTIONS_LEN; i++) {
                if (peerConnections[i].connectionState === "connected" ||
                    peerConnections[i].connectionState === "failed") {
                    peerConnections[i].ontrack = null;
                    peerConnections[i].ondatachannel = null;
                    peerConnections[i].onicecandidate = null;
                    peerConnections[i].onicecandidateerror = null;
                    peerConnections[i].onnegotiationneeded = null;
                    peerConnections[i].onsignalingstatechange = null;
                    peerConnections[i].onconnectionstatechange = null;
                    peerConnections[i].onicegatheringstatechange = null;
                    peerConnections[i].oniceconnectionstatechange = null;
                    peerConnections[i].close();
                }
            }
            return next(action);
        }
        if (setDescription.match(action)) {
            const { peerId, roomId, description, rtcConfig } = action.payload;
            const connectionIndex = peerConnections.findIndex((peer) => peer.withPeerId === peerId);
            const epc = connectionIndex !== -1
                ? peerConnections[connectionIndex]
                : await rtcConnectWithPeer(peerId, roomId, false, rtcConfig);
            const readyForOffer = !epc.makingOffer &&
                (epc.signalingState == "stable" || isSettingRemoteAnswerPending);
            const offerCollision = description.type === "offer" && !readyForOffer;
            // If clientIsInitiator then !polite
            const ignoreOffer = epc.peerIsInitiator && offerCollision;
            if (ignoreOffer)
                return next(action);
            const setPending = description.type === "answer";
            store.dispatch(setIsSettingRemoteAnswerPending(setPending));
            // await epc.setRemoteDescription(description);
            if (offerCollision) {
                await Promise.all([
                    epc.setLocalDescription({ type: "rollback" }),
                    epc.setRemoteDescription(description),
                ]);
            }
            else {
                await epc.setRemoteDescription(description);
            }
            if (setPending)
                store.dispatch(setIsSettingRemoteAnswerPending(false));
            if (description.type == "offer") {
                await epc.setLocalDescription();
                const localDescription = epc.localDescription;
                if (!localDescription) {
                    console.error("Could not generate local description as answer to offer");
                    return next(action);
                }
                store.dispatch(signalingServerActions.sendMessage({
                    content: {
                        type: "description",
                        description: localDescription,
                        toPeerId: peerId,
                    },
                }));
            }
            return next(action);
        }
        if (setCandidate.match(action)) {
            const { peerId, candidate } = action.payload;
            const connectionIndex = peerConnections.findIndex((peer) => peer.withPeerId === peerId);
            if (connectionIndex === -1) {
                iceCandidates.push(Object.assign(candidate, { withPeerId: peerId }));
                return next(action);
            }
            const epc = peerConnections[connectionIndex];
            if (epc.peerIsInitiator && epc.signalingState !== "stable") {
                iceCandidates.push(Object.assign(candidate, {
                    withPeerId: epc.withPeerId,
                }));
            }
            else {
                try {
                    await epc.addIceCandidate(candidate);
                }
                catch (error) {
                    throw error;
                }
            }
            return next(action);
        }
        if (setPeer.match(action)) {
            const { peerId, roomId, initiate, rtcConfig } = action.payload;
            const connectionIndex = peerConnections.findIndex((peer) => {
                peer.withPeerId === peerId;
            });
            if (connectionIndex !== -1)
                return next(action);
            const epc = await rtcConnectWithPeer(peerId, roomId, initiate, rtcConfig);
            peerConnections.push(epc);
        }
        if (setPeerChannel.match(action)) {
            const { label, roomId, withPeerId } = action.payload;
            const connectionIndex = peerConnections.findIndex((peer) => {
                peer.withPeerId === withPeerId;
            });
            if (connectionIndex !== -1)
                return next(action);
            store.dispatch(setChannel({
                label,
                channel: label,
                roomId,
                epc: peerConnections[connectionIndex],
            }));
        }
        return next(action);
    };
};

const roomsMiddleware = (store) => {
    return (next) => async (action) => {
        if (setRoomUrl.match(action)) {
            const { keyPair, rooms } = store.getState();
            const url = action.payload;
            const roomIndex = rooms.findIndex((r) => r.url === url);
            if (roomIndex > -1)
                return next(action);
            store.dispatch(signalingServerActions.sendMessage({
                content: {
                    type: "room",
                    fromPeerId: keyPair.peerId,
                    roomUrl: url,
                },
            }));
        }
        return next(action);
    };
};

const room = configureStore({
    reducer: {
        keyPair: keyPairReducer,
        rooms: roomsReducer,
        peers: peers2Reducer,
        isSettingRemoteAnswerPending: isSettingRemoteAnswerPendingReducer,
        channels: channels2Reducer,
        signalingServer: signalingServerReducer,
    },
    middleware: (getDefaultMiddleware) => getDefaultMiddleware().prepend([
        signalingServerMiddleware,
        channelsMiddleware,
        peersMiddleware,
        roomsMiddleware,
    ]),
});

const connectToSignalingServer = async (signalingServerUrl = "ws://localhost:3001/ws") => {
    room.dispatch(signalingServerActions.startConnecting(signalingServerUrl));
};
const connectToRoom = (roomUrl) => {
    const { keyPair, signalingServer } = room.getState();
    if (signalingServer.isConnected && isUUID(keyPair.peerId)) {
        room.dispatch(setRoomUrl(roomUrl));
    }
};
const connectToRoomPeers = async (roomUrl, httpServerUrl = "http://localhost:3001", rtcConfig = {
    iceServers: [
        {
            urls: ["stun:stun.l.google.com:19302", "stun:stun1.l.google.com:19302"],
        },
    ],
}) => {
    const { keyPair, signalingServer, rooms } = room.getState();
    const roomIndex = rooms.findIndex((r) => r.url === roomUrl);
    if (signalingServer.isConnected && roomIndex > -1) {
        const connectedRoomPeers = await getConnectedRoomPeers(roomUrl, httpServerUrl);
        console.log(connectedRoomPeers);
        const LEN = connectedRoomPeers.length;
        for (let i = 0; i < LEN; i++) {
            if (connectedRoomPeers[i].publicKey === keyPair.publicKey)
                continue;
            room.dispatch(setPeer({
                roomId: connectedRoomPeers[i].roomId,
                peerId: connectedRoomPeers[i].id,
                peerPublicKey: connectedRoomPeers[i].publicKey,
                initiate: true,
                rtcConfig,
            }));
        }
    }
};
const disconnectFromSignalingServer = async () => {
    room.dispatch(signalingServerActions.disconnect());
};
const disconnectFromRoom = async (roomId, _deleteMessages = false) => {
    const { channels } = room.getState();
    let channelIndex = channels.findIndex((c) => {
        c.roomId === roomId;
    });
    while (channelIndex > -1) {
        room.dispatch(deleteLabelChannels({
            channel: channels[channelIndex].label,
        }));
        channelIndex = channels.findIndex((c) => {
            c.roomId === roomId;
        });
    }
    // await rtcDisconnectFromRoom(deleteMessages);
};
const openChannel = async (label, roomId, withPeerIds) => {
    const { peers, channels } = room.getState();
    const PEERS_LEN = withPeerIds && withPeerIds.length > 0 ? withPeerIds.length : peers.length;
    if (PEERS_LEN === 0)
        throw new Error("Cannot open channel with no peers");
    for (let i = 0; i < PEERS_LEN; i++) {
        const peerIndex = withPeerIds && withPeerIds.length > 0
            ? peers.findIndex((p) => {
                p.id === withPeerIds[i];
            })
            : i;
        const channelIndex = channels.findIndex((channel) => channel.withPeerId === peers[peerIndex].id && channel.label === label);
        if (channelIndex > -1)
            continue; // || peers[i].connectionState !== "connected") continue;
        room.dispatch(setPeerChannel({
            label,
            roomId,
            withPeerId: peers[peerIndex].id,
        }));
    }
};
const sendMessage = async (message, toChannel) => {
    const { keyPair } = room.getState();
    room.dispatch(sendMessageToChannel({
        message,
        fromPeerId: keyPair.peerId,
        channel: toChannel,
    }));
};
var index = {
    room,
    signalingServerSelector,
    peersSelector,
    roomsSelector,
    keyPairSelector,
    channelsSelector,
    connectToSignalingServer,
    connectToRoom,
    connectToRoomPeers,
    disconnectFromSignalingServer,
    disconnectFromRoom,
    openChannel,
    sendMessage,
};

exports.default = index;
//# sourceMappingURL=index.js.map
