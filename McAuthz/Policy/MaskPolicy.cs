using McAuthz.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;

namespace McAuthz.Policy {

    /// <summary>
    /// A policy that masks properties of a model based on a list of property names.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    public class MaskPolicy: RulePolicyBase, RulePolicy {

        public MaskPolicy() { }

        public MaskPolicy(string typeName)
        {
            TargetType = typeName;
        }

        public MaskPolicy(Type type)
        {
            TargetType = type.Name;
        }

        public MaskPolicy(string typeName, params string[] properties)
        {
            TargetType = typeName;
            ((List<string>)PropertyList).AddRange(properties);
        }

        public MaskPolicy(Type type, params string[] properties)
        {
            TargetType = type.Name;
            ((List<string>)PropertyList).AddRange(properties);
        }

        public IEnumerable<string> PropertyList { get; set; } = new List<string>();

        public object MaskModel(object model)
        {
            throw new NotImplementedException();
        }
    }

    public class MaskPolicy<T>: RulePolicyBase, RulePolicy {

        public MaskPolicy() {
            TargetType = typeof(T).Name;
        }

        public MaskPolicy(params string[] properties)
        {
            TargetType = typeof(T).Name;
            ((List<string>)PropertyList).AddRange(properties);
        }

        public IEnumerable<string> PropertyList { get; set; } = new List<string>();

        /// <summary>
        /// Applies the mask to the given model, returning a new instance of T with only the specified properties.
        /// All non-sepcified properties will be set to their default values.
        /// </summary>
        /// <param name="model"></param>
        /// <returns></returns>
        public T ApplyMask(T model)
        {
            var props = PropertyList.ToArray();
            var maskExpr = DynamicTypeRegistry.DynamicSelector<T>(props, true);
            var mask = maskExpr.Compile();
            var masked = mask(model);

            return masked;
        }
    }
}