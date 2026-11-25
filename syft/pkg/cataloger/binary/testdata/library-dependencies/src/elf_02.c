extern const char *syft_02_identity(void);
int main(void) {
    return syft_02_identity()[0] == 's' ? 0 : 1;
}
