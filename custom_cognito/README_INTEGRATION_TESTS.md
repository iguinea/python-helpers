# Tests de Integración con AWS Cognito Real

Este documento describe cómo ejecutar los tests de integración que se conectan a un User Pool real de AWS Cognito.

## ⚠️ ADVERTENCIA

**Estos tests crearán usuarios reales en tu User Pool de Cognito.** Solo ejecuta estos tests contra un User Pool de desarrollo/testing.

## Configuración Previa

1. **Configura el archivo `.env`** con las credenciales reales de tu User Pool:
   ```env
   COGNITO_USER_POOL_ID=eu-west-1_alehop
   COGNITO_APP_CLIENT_ID=asdfghjklñqwertyuio
   AWS_REGION=eu-west-1
   ```

2. **Asegúrate de tener credenciales AWS configuradas**:
   - Usando variables de entorno: `AWS_ACCESS_KEY_ID` y `AWS_SECRET_ACCESS_KEY`
   - O usando AWS CLI: `aws configure`
   - O usando un perfil AWS: `AWS_PROFILE=tu-perfil`

## Ejecutar Tests de Integración

### Solo tests de integración real
```bash
cd custom_cognito
pytest -m integration_real tests/
```

### Tests de integración real específicos
```bash
# Solo un test específico
pytest -m integration_real tests/test_integration_real_cognito.py::TestRealCognitoIntegration::test_real_register_and_cleanup

# Solo una clase de tests
pytest -m integration_real tests/test_integration_real_cognito.py::TestRealCognitoIntegration
```

### Excluir tests de integración real (comportamiento por defecto)
```bash
pytest tests/  # Los tests de integración real están excluidos por defecto
```

## Tests Disponibles

### Tests Automáticos

1. **test_real_register_and_cleanup**: Registra un usuario de prueba y lo elimina automáticamente
2. **test_real_duplicate_registration**: Verifica que no se puedan registrar emails duplicados
3. **test_real_password_reset_initiation**: Inicia el proceso de reset de contraseña
4. **test_real_login_unconfirmed_user**: Verifica que usuarios no confirmados no puedan hacer login
5. **test_real_invalid_login**: Verifica el manejo de credenciales inválidas
6. **test_real_jwt_validation**: Valida la obtención de JWKS real
7. **test_real_secret_hash_generation**: Prueba la generación de hash secreto
8. **test_real_cognito_client_initialization**: Verifica la conexión con Cognito

### Tests Manuales (Omitidos por defecto)

- **test_real_full_login_flow**: Requiere confirmación manual del email. Para ejecutarlo:
  1. Descomenta el test (quita `@pytest.mark.skip`)
  2. Usa un email real al que tengas acceso
  3. Ejecuta el test
  4. Revisa el email y obtén el código de confirmación
  5. Actualiza el código en el test
  6. Ejecuta el test nuevamente

## Limpieza de Usuarios de Prueba

Los tests incluyen un fixture `cleanup_users` que automáticamente elimina los usuarios creados durante las pruebas.

### Limpieza Manual

Si necesitas limpiar usuarios manualmente:

```python
from custom_cognito.tests.test_integration_real_cognito import cleanup_specific_user
from custom_cognito.config import Settings

settings = Settings(_env_file=".env")
cleanup_specific_user("test_email@example.com", settings)
```

## Mejores Prácticas

1. **Usa un User Pool de desarrollo** dedicado para tests
2. **No ejecutes estos tests en CI/CD** a menos que tengas un ambiente aislado
3. **Revisa los logs** para verificar que los usuarios se eliminaron correctamente
4. **Usa emails únicos** - los tests generan emails con timestamp para evitar conflictos

## Solución de Problemas

### Error: "An error occurred (NotAuthorizedException)"
- Verifica que las credenciales AWS estén configuradas correctamente
- Asegúrate de que el usuario IAM tenga permisos sobre el User Pool

### Error: "User pool does not exist"
- Verifica que el `COGNITO_USER_POOL_ID` sea correcto
- Confirma que la región AWS sea la correcta

### Los usuarios no se eliminan
- Verifica los permisos IAM para `AdminDeleteUser`
- Revisa los logs del fixture `cleanup_users`