using System;
using System.Linq.Expressions;
using System.Reflection;

namespace frɪdʒ.utils
{
	internal static class ReflectionUtils
	{
		public static Action<T> GetMethodInvoker<T>(string name)
		{
			var type = typeof(T);
			var target = Expression.Parameter(type);
			var method = type.GetMethod(name, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			return (Action<T>)Expression.Lambda(typeof(Action<T>), Expression.Call(target, method), target).Compile();
		}

		public static Action<T, TArg> GetFieldMethodInvoker<T, TArg>(string fieldName, string methodName)
		{
			var type = typeof(T);
			var target = Expression.Parameter(type);
			var field = type.GetField(fieldName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			var method = field.FieldType.GetMethod(methodName, BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);
			var arg = Expression.Parameter(typeof(TArg));
			return (Action<T, TArg>)Expression.Lambda(typeof(Action<T, TArg>), Expression.Call(Expression.Field(target, field), method, arg), target, arg).Compile();
		}
	}
}